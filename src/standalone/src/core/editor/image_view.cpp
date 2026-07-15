#include "image_view.hpp"

#include "imgui/imgui.h"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../helpers/stb_image.h"
#include "../../helpers/diag_log.hpp"
#endif
#include "theme.hpp"

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <windows.h>
#include <d3d11.h>
#endif

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <thread>

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
extern ID3D11Device* g_pd3dDevice;
#endif

namespace image_view {

state_t& g_state()
{
	static state_t s;
	return s;
}

bool is_image_extension(const std::string& ext_lower)
{
	static const char* exts[] = {
		".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tga",
		".psd", ".hdr", ".pic", ".ppm", ".pgm"
	};
	for (auto* e : exts)
		if (ext_lower == e) return true;
	return false;
}

static void release_srv()
{
	state_t& s = g_state();
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (s.srv) {
		s.srv->Release();
		s.srv = nullptr;
	}
#else
	s.srv = nullptr;
#endif
	s.pixels.clear();
	s.pixels.shrink_to_fit();
	s.width = 0;
	s.height = 0;
	s.channels = 0;
	s.ready.store(false, std::memory_order_release);
	s.active.store(false, std::memory_order_release);
}

void clear()
{
	state_t& s = g_state();
	release_srv();
	s.path.clear();
	s.filename.clear();
	s.err.clear();
	s.zoom = 1.f;
	s.target_zoom = 1.f;
	s.pan_x = 0.f;
	s.pan_y = 0.f;
	s.fit_to_view = true;
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
static bool upload_to_gpu(const uint8_t* pixels, int w, int h)
{
	state_t& s = g_state();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (!pixels || w <= 0 || h <= 0) return false;
	s.width = w;
	s.height = h;
	return true;
#else
	if (!g_pd3dDevice || !pixels || w <= 0 || h <= 0) return false;

	D3D11_TEXTURE2D_DESC desc = {};
	desc.Width = static_cast<UINT>(w);
	desc.Height = static_cast<UINT>(h);
	desc.MipLevels = 1;
	desc.ArraySize = 1;
	desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	desc.SampleDesc.Count = 1;
	desc.Usage = D3D11_USAGE_DEFAULT;
	desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

	D3D11_SUBRESOURCE_DATA sd = {};
	sd.pSysMem = pixels;
	sd.SysMemPitch = static_cast<UINT>(w) * 4u;

	ID3D11Texture2D* tex = nullptr;
	HRESULT hr = g_pd3dDevice->CreateTexture2D(&desc, &sd, &tex);
	if (FAILED(hr) || !tex) {
		diag::log_tagged_fmt("image_view",
			"upload_to_gpu CreateTexture2D failed hr=0x%lx w=%d h=%d",
			static_cast<unsigned long>(hr), w, h);
		return false;
	}

	ID3D11ShaderResourceView* srv = nullptr;
	hr = g_pd3dDevice->CreateShaderResourceView(tex, nullptr, &srv);
	tex->Release();
	if (FAILED(hr) || !srv) {
		diag::log_tagged_fmt("image_view",
			"upload_to_gpu CreateShaderResourceView failed hr=0x%lx",
			static_cast<unsigned long>(hr));
		return false;
	}

	release_srv();
	s.srv = srv;
	s.width = w;
	s.height = h;
	return true;
#endif
}
#endif

bool load_from_file(const std::string& path)
{
	state_t& s = g_state();
	clear();
	s.path = path;
	{
		size_t sl = path.find_last_of("/\\");
		s.filename = (sl != std::string::npos) ? path.substr(sl + 1) : path;
	}
	s.loading.store(true, std::memory_order_release);
	s.active.store(true, std::memory_order_release);

	int w = 0, h = 0, ch = 0;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	w = 960;
	h = 540;
	ch = 4;
	s.pixels.resize(64u * 36u * 4u);
	for (int py = 0; py < 36; ++py) {
		for (int px = 0; px < 64; ++px) {
			const std::size_t offset = static_cast<std::size_t>(py * 64 + px) * 4u;
			const float nx = static_cast<float>(px) / 63.f;
			const float ny = static_cast<float>(py) / 35.f;
			const float glow = (std::max)(0.f, 1.f - std::sqrt((nx - 0.56f) * (nx - 0.56f) + (ny - 0.46f) * (ny - 0.46f)) * 2.4f);
			s.pixels[offset + 0] = static_cast<std::uint8_t>(12.f + glow * 32.f);
			s.pixels[offset + 1] = static_cast<std::uint8_t>(20.f + glow * 76.f);
			s.pixels[offset + 2] = static_cast<std::uint8_t>(34.f + glow * 154.f);
			s.pixels[offset + 3] = 255;
		}
	}
	s.width = w;
	s.height = h;
	s.channels = ch;
	s.last_load_ms = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count());
	s.loading.store(false, std::memory_order_release);
	s.ready.store(true, std::memory_order_release);
	return true;
#else
	diag::log_tagged_fmt("image_view", "load_begin path=%s", path.c_str());
	unsigned char* px = stbi_load(path.c_str(), &w, &h, &ch, 4);
	if (!px) {
		s.err = stbi_failure_reason() ? stbi_failure_reason() : "stbi_load failed";
		s.loading.store(false, std::memory_order_release);
		s.ready.store(false, std::memory_order_release);
		diag::log_tagged_fmt("image_view", "load_failed path=%s err=%s",
			path.c_str(), s.err.c_str());
		return false;
	}

	bool uploaded = upload_to_gpu(px, w, h);
	if (!uploaded) {
		s.channels = ch;
		s.pixels.assign(px, px + (size_t)w * (size_t)h * 4u);
		s.width = w;
		s.height = h;
	} else {
		s.channels = ch;
	}
	stbi_image_free(px);

	s.last_load_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count();
	s.loading.store(false, std::memory_order_release);
	s.ready.store(uploaded, std::memory_order_release);
	diag::log_tagged_fmt("image_view",
		"load_done path=%s w=%d h=%d ch=%d uploaded=%d",
		path.c_str(), w, h, ch, uploaded ? 1 : 0);
	return uploaded;
#endif
}

void render(float x, float y, float w, float h, float alpha,
            float ax3, float ay3, float az3)
{
	(void)ax3; (void)ay3; (void)az3;
	state_t& s = g_state();
	if (!s.active.load(std::memory_order_acquire)) return;

	const auto& th = aida::ui::resolved();

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	ImVec2 pmin(wp.x + x, wp.y + y);
	ImVec2 pmax(wp.x + x + w, wp.y + y + h);

	dl->AddRectFilled(pmin, pmax, aida::ui::with_alpha(th.bg_base, alpha));

	bool loading = s.loading.load(std::memory_order_acquire);
	bool ready = s.ready.load(std::memory_order_acquire);

	if (loading) {
		const char* msg = "Decoding image...";
		ImVec2 ts = ImGui::CalcTextSize(msg);
		dl->AddText(ImVec2(pmin.x + (w - ts.x) * 0.5f, pmin.y + (h - ts.y) * 0.5f),
			aida::ui::with_alpha(th.text_dim, alpha), msg);
		return;
	}

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const bool drawable = ready && !s.pixels.empty() && s.width > 0 && s.height > 0;
#else
	const bool drawable = ready && s.srv != nullptr && s.width > 0 && s.height > 0;
#endif
	if (!drawable) {
		std::string msg = s.err.empty() ? "Unable to display image" : ("Image error: " + s.err);
		ImVec2 ts = ImGui::CalcTextSize(msg.c_str());
		dl->AddText(ImVec2(pmin.x + (w - ts.x) * 0.5f, pmin.y + (h - ts.y) * 0.5f),
			aida::ui::with_alpha(th.text_dim, alpha), msg.c_str());
		return;
	}

	const float toolbar_h = 30.f;
	ImVec2 cmin(pmin.x, pmin.y + toolbar_h);
	ImVec2 cmax(pmax.x, pmax.y);
	float cw = cmax.x - cmin.x;
	float ch_avail = cmax.y - cmin.y;
	if (cw <= 1.f || ch_avail <= 1.f) return;

	dl->AddRectFilled(pmin, ImVec2(pmax.x, pmin.y + toolbar_h),
		aida::ui::with_alpha(th.panel_header, alpha));
	dl->AddText(ImVec2(pmin.x + 10.f, pmin.y + (toolbar_h - ImGui::GetFontSize()) * 0.5f),
		aida::ui::with_alpha(th.text_primary, alpha), s.filename.c_str());

	char info[96];
	std::snprintf(info, sizeof(info), "%dx%d  zoom %.0f%%",
		s.width, s.height, s.zoom * 100.f);
	ImVec2 its = ImGui::CalcTextSize(info);
	dl->AddText(ImVec2(pmax.x - its.x - 12.f, pmin.y + (toolbar_h - its.y) * 0.5f),
		aida::ui::with_alpha(th.text_dim, alpha), info);

	if (s.fit_to_view) {
		float fx = cw / (float)s.width;
		float fy = ch_avail / (float)s.height;
		float f = std::min(fx, fy);
		if (f > 1.f) f = 1.f;
		s.target_zoom = f;
		s.zoom = f;
		s.pan_x = 0.f;
		s.pan_y = 0.f;
	}

	bool hovering = ImGui::IsMouseHoveringRect(cmin, cmax, false);
	ImGuiIO& io = ImGui::GetIO();
	if (hovering && std::fabs(io.MouseWheel) > 0.001f) {
		float prev = s.target_zoom;
		float factor = (io.MouseWheel > 0.f) ? 1.15f : (1.f / 1.15f);
		s.target_zoom = std::clamp(s.target_zoom * factor, 0.05f, 32.f);
		s.fit_to_view = false;
		float mx = io.MousePos.x - (cmin.x + cw * 0.5f) - s.pan_x;
		float my = io.MousePos.y - (cmin.y + ch_avail * 0.5f) - s.pan_y;
		float ratio = (prev > 0.0001f) ? (s.target_zoom / prev) : 1.f;
		s.pan_x -= mx * (ratio - 1.f);
		s.pan_y -= my * (ratio - 1.f);
	}
	if (hovering && ImGui::IsMouseDragging(ImGuiMouseButton_Left, 2.f)) {
		ImVec2 d = ImGui::GetMouseDragDelta(ImGuiMouseButton_Left, 2.f);
		s.pan_x += d.x;
		s.pan_y += d.y;
		ImGui::ResetMouseDragDelta(ImGuiMouseButton_Left);
		s.fit_to_view = false;
	}
	if (hovering && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
		s.fit_to_view = true;
		s.target_zoom = 1.f;
		s.zoom = 1.f;
		s.pan_x = 0.f;
		s.pan_y = 0.f;
	}

	float dt = io.DeltaTime;
	float k = std::min(20.f * dt, 1.f);
	s.zoom += (s.target_zoom - s.zoom) * k;

	float disp_w = (float)s.width * s.zoom;
	float disp_h = (float)s.height * s.zoom;
	float cx = cmin.x + (cw - disp_w) * 0.5f + s.pan_x;
	float cy = cmin.y + (ch_avail - disp_h) * 0.5f + s.pan_y;

	dl->PushClipRect(cmin, cmax, true);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const int preview_w = 64;
	const int preview_h = 36;
	const float cell_w = disp_w / static_cast<float>(preview_w);
	const float cell_h = disp_h / static_cast<float>(preview_h);
	for (int py = 0; py < preview_h; ++py) {
		for (int px = 0; px < preview_w; ++px) {
			const std::size_t offset = static_cast<std::size_t>(py * preview_w + px) * 4u;
			const ImU32 color = IM_COL32(s.pixels[offset], s.pixels[offset + 1], s.pixels[offset + 2], static_cast<int>(255.f * alpha));
			dl->AddRectFilled(
				ImVec2(cx + cell_w * static_cast<float>(px), cy + cell_h * static_cast<float>(py)),
				ImVec2(cx + cell_w * static_cast<float>(px + 1), cy + cell_h * static_cast<float>(py + 1)),
				color);
		}
	}
#else
	dl->AddImage(reinterpret_cast<ImTextureID>(s.srv),
		ImVec2(cx, cy), ImVec2(cx + disp_w, cy + disp_h),
		ImVec2(0, 0), ImVec2(1, 1),
		IM_COL32(255, 255, 255, (int)(255 * alpha)));
#endif
	dl->PopClipRect();
}

}
