#pragma once

#include <cmath>
#include <cstdint>

namespace aida::motion {

	struct spring_t {
		float stiffness;
		float damping;
	};

	namespace dur {
		constexpr float xs  = 0.080f;
		constexpr float sm  = 0.140f;
		constexpr float md  = 0.220f;
		constexpr float lg  = 0.320f;
		constexpr float xl  = 0.480f;
		constexpr float xxl = 0.720f;
		constexpr float hero= 1.200f;
	}

	namespace spring {
		constexpr spring_t gentle  { 170.f, 22.f };
		constexpr spring_t balanced{ 180.f, 14.f };
		constexpr spring_t snappy  { 240.f, 22.f };
		constexpr spring_t playful { 220.f, 11.f };
		constexpr spring_t stiff   { 320.f, 30.f };
		constexpr spring_t wobbly  { 180.f, 8.f  };
	}

	namespace ease {

		inline float clamp01(float t) {
			if (t < 0.f) return 0.f;
			if (t > 1.f) return 1.f;
			return t;
		}

		inline float linear(float t) { return clamp01(t); }

		inline float in_quad(float t) {
			t = clamp01(t);
			return t * t;
		}
		inline float out_quad(float t) {
			t = clamp01(t);
			return 1.f - (1.f - t) * (1.f - t);
		}
		inline float in_out_quad(float t) {
			t = clamp01(t);
			return t < 0.5f ? 2.f * t * t : 1.f - (-2.f * t + 2.f) * (-2.f * t + 2.f) / 2.f;
		}

		inline float in_cubic(float t) {
			t = clamp01(t);
			return t * t * t;
		}
		inline float out_cubic(float t) {
			t = clamp01(t);
			float u = 1.f - t;
			return 1.f - u * u * u;
		}
		inline float in_out_cubic(float t) {
			t = clamp01(t);
			return t < 0.5f ? 4.f * t * t * t
			                : 1.f - powf(-2.f * t + 2.f, 3.f) / 2.f;
		}

		inline float in_quint(float t) {
			t = clamp01(t);
			return t * t * t * t * t;
		}
		inline float out_quint(float t) {
			t = clamp01(t);
			float u = 1.f - t;
			return 1.f - u * u * u * u * u;
		}
		inline float in_out_quint(float t) {
			t = clamp01(t);
			return t < 0.5f ? 16.f * t * t * t * t * t
			                : 1.f - powf(-2.f * t + 2.f, 5.f) / 2.f;
		}

		inline float in_back(float t) {
			t = clamp01(t);
			constexpr float c1 = 1.70158f;
			constexpr float c3 = c1 + 1.f;
			return c3 * t * t * t - c1 * t * t;
		}
		inline float out_back(float t) {
			t = clamp01(t);
			constexpr float c1 = 1.70158f;
			constexpr float c3 = c1 + 1.f;
			float u = t - 1.f;
			return 1.f + c3 * u * u * u + c1 * u * u;
		}
		inline float in_out_back(float t) {
			t = clamp01(t);
			constexpr float c1 = 1.70158f;
			constexpr float c2 = c1 * 1.525f;
			return t < 0.5f
				? (powf(2.f * t, 2.f) * ((c2 + 1.f) * 2.f * t - c2)) / 2.f
				: (powf(2.f * t - 2.f, 2.f) * ((c2 + 1.f) * (t * 2.f - 2.f) + c2) + 2.f) / 2.f;
		}

		inline float out_elastic(float t) {
			t = clamp01(t);
			if (t == 0.f || t == 1.f) return t;
			constexpr float c4 = 6.2831853f / 3.f;
			return powf(2.f, -10.f * t) * sinf((t * 10.f - 0.75f) * c4) + 1.f;
		}

		inline float out_bounce(float t) {
			t = clamp01(t);
			constexpr float n1 = 7.5625f;
			constexpr float d1 = 2.75f;
			if (t < 1.f / d1) return n1 * t * t;
			if (t < 2.f / d1) { t -= 1.5f / d1;  return n1 * t * t + 0.75f; }
			if (t < 2.5f / d1){ t -= 2.25f / d1; return n1 * t * t + 0.9375f; }
			t -= 2.625f / d1;
			return n1 * t * t + 0.984375f;
		}

		inline float in_out_circ(float t) {
			t = clamp01(t);
			return t < 0.5f
				? (1.f - sqrtf(1.f - 4.f * t * t)) / 2.f
				: (sqrtf(1.f - powf(-2.f * t + 2.f, 2.f)) + 1.f) / 2.f;
		}

		inline float bezier(float p1x, float p1y, float p2x, float p2y, float t) {
			t = clamp01(t);
			float u = 1.f - t;
			float y = 3.f * u * u * t * p1y + 3.f * u * t * t * p2y + t * t * t;
			(void)p1x; (void)p2x;
			return y;
		}
	}

	inline float smooth_lerp(float current, float target, float speed, float dt) {
		float a = speed * dt;
		if (a > 1.f) a = 1.f;
		if (a < 0.f) a = 0.f;
		return current + (target - current) * a;
	}

	inline float critically_damped_step(float current, float target,
	                                     float& velocity, float halflife,
	                                     float dt) {
		if (halflife <= 0.0001f) { current = target; velocity = 0.f; return current; }
		float ln2 = 0.693147f;
		float lambda = ln2 / halflife;
		float dx = current - target;
		float exp_term = expf(-lambda * dt);
		float new_dx = (dx + (velocity + lambda * dx) * dt) * exp_term;
		float new_v  = (velocity - lambda * (velocity + lambda * dx) * dt) * exp_term;
		velocity = new_v;
		return target + new_dx;
	}

	inline float spring_step(float current, float target, float& velocity,
	                          spring_t s, float dt) {
		if (dt > 0.04f) dt = 0.04f;
		float ks = s.stiffness;
		float kd = s.damping;
		float force = -ks * (current - target) - kd * velocity;
		velocity += force * dt;
		current  += velocity * dt;
		return current;
	}

	inline float color_lerp_channel(float a, float b, float t) {
		if (t < 0.f) t = 0.f;
		if (t > 1.f) t = 1.f;
		return a + (b - a) * t;
	}

	inline float remap(float v, float in_min, float in_max, float out_min, float out_max) {
		if (in_max - in_min < 0.0001f) return out_min;
		float t = (v - in_min) / (in_max - in_min);
		if (t < 0.f) t = 0.f;
		if (t > 1.f) t = 1.f;
		return out_min + (out_max - out_min) * t;
	}

}
