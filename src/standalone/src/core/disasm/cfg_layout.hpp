#pragma once

#include <algorithm>
#include <cstdint>
#include <map>
#include <queue>
#include <vector>

namespace cfg_layout {

struct node_t {
	int   id = 0;
	float x = 0.f;
	float y = 0.f;
	float width = 200.f;
	float height = 100.f;
	float addr_col_w = 80.f;
	int   layer = -1;
	bool  is_entry = false;
};

struct edge_t {
	int  from = 0;
	int  to = 0;
	bool is_true_branch = false;
};

struct graph_t {
	std::vector<node_t> nodes;
	std::vector<edge_t> edges;
};

namespace detail {

inline std::map<int, std::vector<int>> build_adj(const graph_t& g)
{
	std::map<int, std::vector<int>> adj;
	for (auto& n : g.nodes)
		adj[n.id];
	for (auto& e : g.edges)
		adj[e.from].push_back(e.to);
	return adj;
}

inline std::map<int, std::vector<int>> build_pred(const graph_t& g)
{
	std::map<int, std::vector<int>> pred;
	for (auto& n : g.nodes)
		pred[n.id];
	for (auto& e : g.edges)
		pred[e.to].push_back(e.from);
	return pred;
}

inline int find_node_index(const graph_t& g, int id)
{
	for (int i = 0; i < static_cast<int>(g.nodes.size()); ++i) {
		if (g.nodes[i].id == id)
			return i;
	}
	return -1;
}

}

inline void layout(graph_t& graph, float node_spacing_x, float node_spacing_y)
{
	if (graph.nodes.empty())
		return;

	auto adj = detail::build_adj(graph);
	auto pred = detail::build_pred(graph);

	std::map<int, int> id_to_idx;
	for (int i = 0; i < static_cast<int>(graph.nodes.size()); ++i)
		id_to_idx[graph.nodes[i].id] = i;

	for (auto& n : graph.nodes)
		n.layer = -1;

	int entry_idx = -1;
	for (int i = 0; i < static_cast<int>(graph.nodes.size()); ++i) {
		if (graph.nodes[i].is_entry) { entry_idx = i; break; }
	}
	if (entry_idx < 0) entry_idx = detail::find_node_index(graph, 0);
	if (entry_idx < 0) entry_idx = 0;
	graph.nodes[entry_idx].layer = 0;

	std::queue<int> bfs_queue;
	bfs_queue.push(graph.nodes[entry_idx].id);

	std::map<int, bool> visited;
	visited[graph.nodes[entry_idx].id] = true;

	while (!bfs_queue.empty()) {
		int cur = bfs_queue.front();
		bfs_queue.pop();

		int cur_idx = id_to_idx[cur];
		int cur_layer = graph.nodes[cur_idx].layer;

		for (int succ : adj[cur]) {
			int succ_idx = id_to_idx[succ];
			int new_layer = cur_layer + 1;
			if (graph.nodes[succ_idx].layer < new_layer)
				graph.nodes[succ_idx].layer = new_layer;

			if (!visited[succ]) {
				visited[succ] = true;
				bfs_queue.push(succ);
			}
		}
	}

	int max_layer = 0;
	for (auto& n : graph.nodes) {
		if (n.layer > max_layer)
			max_layer = n.layer;
	}

	int next_layer = max_layer + 1;
	for (auto& n : graph.nodes) {
		if (n.layer < 0) {
			n.layer = next_layer++;
		}
	}

	max_layer = 0;
	for (auto& n : graph.nodes) {
		if (n.layer > max_layer)
			max_layer = n.layer;
	}

	std::vector<std::vector<int>> layers(max_layer + 1);
	for (auto& n : graph.nodes)
		layers[n.layer].push_back(n.id);

	for (int layer = 1; layer <= max_layer; ++layer) {
		auto& ids = layers[layer];
		std::vector<std::pair<float, int>> scored;
		scored.reserve(ids.size());

		for (int nid : ids) {
			auto& preds = pred[nid];
			float avg_x = 0.f;
			int count = 0;
			for (int pid : preds) {
				int pidx = id_to_idx[pid];
				avg_x += graph.nodes[pidx].x;
				++count;
			}
			if (count > 0) avg_x /= static_cast<float>(count);
			scored.push_back({avg_x, nid});
		}

		std::sort(scored.begin(), scored.end(), [](const auto& a, const auto& b) {
			return a.first < b.first;
		});

		ids.clear();
		for (auto& s : scored)
			ids.push_back(s.second);
	}

	std::vector<float> layer_max_h(max_layer + 1, 0.f);
	for (auto& n : graph.nodes) {
		if (layer_max_h[n.layer] < n.height)
			layer_max_h[n.layer] = n.height;
	}

	std::vector<float> layer_y(max_layer + 1, 0.f);
	float cum_y = 0.f;
	for (int l = 0; l <= max_layer; ++l) {
		layer_y[l] = cum_y;
		cum_y += layer_max_h[l] + node_spacing_y;
	}

	for (int layer = 0; layer <= max_layer; ++layer) {
		auto& ids = layers[layer];
		int count = static_cast<int>(ids.size());
		float total_width = 0.f;
		for (int nid : ids) {
			int idx = id_to_idx[nid];
			total_width += graph.nodes[idx].width;
		}
		total_width += static_cast<float>(count > 0 ? count - 1 : 0) * node_spacing_x;

		float start_x = -total_width * 0.5f;
		float cur_x = start_x;

		for (int nid : ids) {
			int idx = id_to_idx[nid];
			graph.nodes[idx].x = cur_x + graph.nodes[idx].width * 0.5f;
			graph.nodes[idx].y = layer_y[layer];
			cur_x += graph.nodes[idx].width + node_spacing_x;
		}
	}

	for (int pass = 0; pass < 4; ++pass) {
		for (int layer = 1; layer <= max_layer; ++layer) {
			auto& ids = layers[layer];
			for (int nid : ids) {
				auto& preds = pred[nid];
				if (preds.empty()) continue;
				float avg_x = 0.f;
				for (int pid : preds)
					avg_x += graph.nodes[id_to_idx[pid]].x;
				avg_x /= static_cast<float>(preds.size());
				int idx = id_to_idx[nid];
				graph.nodes[idx].x = graph.nodes[idx].x * 0.5f + avg_x * 0.5f;
			}
		}

		for (int layer = max_layer - 1; layer >= 0; --layer) {
			auto& ids = layers[layer];
			for (int nid : ids) {
				auto& succs = adj[nid];
				if (succs.empty()) continue;
				float avg_x = 0.f;
				for (int sid : succs)
					avg_x += graph.nodes[id_to_idx[sid]].x;
				avg_x /= static_cast<float>(succs.size());
				int idx = id_to_idx[nid];
				graph.nodes[idx].x = graph.nodes[idx].x * 0.5f + avg_x * 0.5f;
			}
		}

		for (int layer = 0; layer <= max_layer; ++layer) {
			auto& ids = layers[layer];
			if (ids.size() < 2) continue;
			std::sort(ids.begin(), ids.end(), [&](int a, int b) {
				return graph.nodes[id_to_idx[a]].x < graph.nodes[id_to_idx[b]].x;
			});
			for (int i = 1; i < static_cast<int>(ids.size()); ++i) {
				int prev_idx = id_to_idx[ids[i - 1]];
				int cur_idx  = id_to_idx[ids[i]];
				float prev_right = graph.nodes[prev_idx].x + graph.nodes[prev_idx].width * 0.5f;
				float cur_left   = graph.nodes[cur_idx].x  - graph.nodes[cur_idx].width  * 0.5f;
				float min_gap = node_spacing_x;
				float gap = cur_left - prev_right;
				if (gap < min_gap) {
					float push = min_gap - gap;
					graph.nodes[cur_idx].x += push;
				}
			}
			for (int i = static_cast<int>(ids.size()) - 2; i >= 0; --i) {
				int next_idx = id_to_idx[ids[i + 1]];
				int cur_idx  = id_to_idx[ids[i]];
				float next_left  = graph.nodes[next_idx].x - graph.nodes[next_idx].width * 0.5f;
				float cur_right  = graph.nodes[cur_idx].x  + graph.nodes[cur_idx].width  * 0.5f;
				float min_gap = node_spacing_x;
				float gap = next_left - cur_right;
				if (gap < min_gap) {
					float pull = min_gap - gap;
					graph.nodes[cur_idx].x -= pull * 0.5f;
				}
			}
		}
	}
}

}
