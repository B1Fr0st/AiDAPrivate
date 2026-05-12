#pragma once

#include "motion.hpp"
#include "clock.hpp"
#include <functional>

namespace aida::ui {

	using ease_fn = float(*)(float);

	struct transition_t {
		float    progress = 0.f;
		float    duration = aida::motion::dur::md;
		ease_fn  curve = aida::motion::ease::out_cubic;
		float    delay = 0.f;
		float    delay_remaining = 0.f;
		bool     active = false;
		bool     reverse_on_interrupt = true;
		bool     direction_forward = true;

		void start(float dur, ease_fn c = aida::motion::ease::out_cubic, float delay_s = 0.f) {
			duration = dur > 0.0001f ? dur : 0.0001f;
			curve = c ? c : aida::motion::ease::linear;
			active = true;
			direction_forward = true;
			delay = delay_s;
			delay_remaining = delay_s;
			progress = 0.f;
		}

		void start_reverse(float dur, ease_fn c = aida::motion::ease::out_cubic) {
			duration = dur > 0.0001f ? dur : 0.0001f;
			curve = c ? c : aida::motion::ease::linear;
			active = true;
			direction_forward = false;
			delay_remaining = 0.f;
		}

		void interrupt_to(float new_target_progress) {
			progress = new_target_progress;
		}

		void reset() {
			progress = 0.f;
			active = false;
			direction_forward = true;
			delay_remaining = 0.f;
		}

		void tick(float dt) {
			if (!active) return;
			if (delay_remaining > 0.f) {
				delay_remaining -= dt;
				if (delay_remaining > 0.f) return;
				dt = -delay_remaining;
				delay_remaining = 0.f;
			}
			float step = (dt / duration);
			if (direction_forward) {
				progress += step;
				if (progress >= 1.f) { progress = 1.f; active = false; }
			} else {
				progress -= step;
				if (progress <= 0.f) { progress = 0.f; active = false; }
			}
		}

		float eased() const {
			float p = progress;
			if (p < 0.f) p = 0.f;
			if (p > 1.f) p = 1.f;
			return curve ? curve(p) : p;
		}

		bool is_finished() const { return !active; }
		bool at_origin()  const { return progress <= 0.0001f; }
		bool at_target()  const { return progress >= 0.9999f; }
	};

	struct stagger_group_t {
		transition_t base;
		float        per_item_delay = 0.012f;
		int          item_count = 0;

		void configure(float total_duration, ease_fn c, float per_item) {
			base.start(total_duration, c, 0.f);
			per_item_delay = per_item;
		}

		float at(int idx) const {
			if (per_item_delay <= 0.f) {
				float p = base.progress;
				if (p < 0.f) p = 0.f;
				if (p > 1.f) p = 1.f;
				return base.curve ? base.curve(p) : p;
			}
			float local_t = base.progress - (float)idx * per_item_delay;
			if (local_t < 0.f) return 0.f;
			float total_stagger = (float)(item_count > 0 ? item_count - 1 : 0) * per_item_delay;
			float denom = 1.f - total_stagger;
			if (denom < 0.001f) denom = 1.f;
			float frac = local_t / denom;
			if (frac < 0.f) frac = 0.f;
			if (frac > 1.f) frac = 1.f;
			return base.curve ? base.curve(frac) : frac;
		}

		void tick(float dt) { base.tick(dt); }
	};

	struct hover_state_t {
		float v = 0.f;
		float vel = 0.f;

		float tick(bool hovered, float dt, aida::motion::spring_t s = aida::motion::spring::balanced) {
			float target = hovered ? 1.f : 0.f;
			v = aida::motion::spring_step(v, target, vel, s, dt);
			if (v < 0.f) v = 0.f;
			if (v > 1.f) v = 1.f;
			return v;
		}
	};

	struct press_state_t {
		float v = 0.f;
		float vel = 0.f;

		float tick(bool pressed, float dt) {
			float target = pressed ? 1.f : 0.f;
			v = aida::motion::spring_step(v, target, vel, aida::motion::spring::stiff, dt);
			if (v < 0.f) v = 0.f;
			if (v > 1.f) v = 1.f;
			return v;
		}

		float scale(float min_scale = 0.97f) const {
			return 1.f - (1.f - min_scale) * v;
		}
	};

	struct flash_t {
		float v = 0.f;

		void trigger() { v = 1.f; }
		float tick(float dt, float decay_per_second = 3.f) {
			v -= dt * decay_per_second;
			if (v < 0.f) v = 0.f;
			return v;
		}
	};

	template<typename FA, typename FB>
	inline void render_crossfade(transition_t& t, FA&& draw_a, FB&& draw_b) {
		float e = t.eased();
		if (e < 0.999f) {
			ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * (1.f - e));
			draw_a();
			ImGui::PopStyleVar();
		}
		if (e > 0.001f) {
			ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * e);
			draw_b();
			ImGui::PopStyleVar();
		}
	}

}
