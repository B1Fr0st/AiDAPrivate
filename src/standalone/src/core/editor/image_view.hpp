#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

struct ID3D11ShaderResourceView;

namespace image_view {

struct state_t {
	std::string                       path;
	std::string                       filename;
	std::string                       err;
	int                               width        = 0;
	int                               height       = 0;
	int                               channels     = 0;
	std::vector<uint8_t>              pixels;
	ID3D11ShaderResourceView*         srv          = nullptr;
	std::atomic<bool>                 loading{false};
	std::atomic<bool>                 ready{false};
	std::atomic<bool>                 active{false};
	float                             zoom         = 1.f;
	float                             target_zoom  = 1.f;
	float                             pan_x        = 0.f;
	float                             pan_y        = 0.f;
	bool                              fit_to_view  = true;
	uint64_t                          last_load_ms = 0;
};

state_t& g_state();

bool is_image_extension(const std::string& ext_lower);

bool load_from_file(const std::string& path);

void clear();

void render(float x, float y, float w, float h, float alpha,
            float ax3, float ay3, float az3);

}
