#pragma once
#include "imgui/imgui.h"
#include "keybind.h"
#include <d3d11.h>

extern ID3D11Device* g_pd3dDevice;

struct helpers
{
	static int  active_tab;
	static int  active_subsection;
	static bool init;

	static ID3D11ShaderResourceView* icon_aim;
	static ID3D11ShaderResourceView* icon_see;
	static ID3D11ShaderResourceView* icon_misc;
	static ID3D11ShaderResourceView* icon_player;
	static ID3D11ShaderResourceView* icon_settings;
	static ID3D11ShaderResourceView* icon_solitude;


	static ID3D11ShaderResourceView* theme_rias;
	static ID3D11ShaderResourceView* theme_nagi;
	static ID3D11ShaderResourceView* theme_mio;
	static ID3D11ShaderResourceView* theme_kaneki;
	static bool themes_loaded;

	static int icon_w, icon_h;
	static bool icons_loaded;

	static bool tab(const char* label, int index, ImVec2 pos, ImVec2 size);
	static void begin_child(const char* str_id, ImVec2 pos, ImVec2 size, float alpha = 1.f, ImGuiWindowFlags flags = 0);
	static void end_child();
	static int  subsection(const char** labels, int count, ImVec2 pos);
	static int  subsection(const char** labels, int count, ImVec2 pos, int& state);
	static void add_key(const char* label, CKeybind* keybind);
	static void render_title();
};

namespace icon_loader
{
	bool load(const unsigned char* data, int size, ID3D11ShaderResourceView** out_srv, int* out_w, int* out_h, bool force_white = true);
}

extern HWND g_hwnd;
