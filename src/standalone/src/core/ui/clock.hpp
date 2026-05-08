#pragma once

#include "imgui/imgui.h"
#include <atomic>
#include <cstdint>

namespace aida::ui::clock {

	namespace detail {
		inline std::atomic<uint64_t> s_frame_index{ 0 };
		inline float s_seconds = 0.f;
		inline float s_dt = 0.f;
		inline float s_dt_unscaled = 0.f;
		inline float s_time_scale = 1.f;
		inline bool  s_first_tick = true;
	}

	inline void tick() {
		ImGuiIO& io = ImGui::GetIO();
		float dt = io.DeltaTime;
		if (dt < 0.f) dt = 0.f;
		if (dt > 0.25f) dt = 0.25f;
		detail::s_dt_unscaled = dt;
		detail::s_dt = dt * detail::s_time_scale;
		if (detail::s_first_tick) {
			detail::s_first_tick = false;
			detail::s_dt = 0.f;
		}
		detail::s_seconds += detail::s_dt;
		detail::s_frame_index.fetch_add(1, std::memory_order_relaxed);
	}

	inline float seconds()       { return detail::s_seconds; }
	inline float dt()            { return detail::s_dt; }
	inline float dt_unscaled()   { return detail::s_dt_unscaled; }
	inline uint64_t frame_index(){ return detail::s_frame_index.load(std::memory_order_relaxed); }

	inline void set_time_scale(float s) {
		if (s < 0.f) s = 0.f;
		if (s > 8.f) s = 8.f;
		detail::s_time_scale = s;
	}
	inline float time_scale() { return detail::s_time_scale; }

	inline float pulse(float frequency_hz, float lo = 0.f, float hi = 1.f) {
		float two_pi = 6.2831853f;
		float v = (sinf(detail::s_seconds * two_pi * frequency_hz) * 0.5f) + 0.5f;
		return lo + (hi - lo) * v;
	}

	inline float saw(float period_seconds) {
		if (period_seconds <= 0.0001f) return 0.f;
		float t = detail::s_seconds / period_seconds;
		return t - floorf(t);
	}

	inline float triangle(float period_seconds) {
		float t = saw(period_seconds);
		return t < 0.5f ? (t * 2.f) : (2.f - t * 2.f);
	}

}
