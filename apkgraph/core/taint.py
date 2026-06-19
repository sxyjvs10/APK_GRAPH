"""
TaintEngine v2.0
----------------
Fixes:
- BFS queue was list.pop(0) — O(n) per step. Now uses collections.deque for O(1).
- Added early-exit and visited-set to prevent cycles properly.
- Added depth tracking.
- Added find_all_paths() for exhaustive discovery.
"""
from collections import deque


class TaintEngine:
    def __init__(self, analysis):
        self.analysis = analysis

    def find_paths(self, source_methods, sink_descriptors, max_depth=5):
        """
        Find call paths from source methods to sink descriptors.
        Returns the first path found per source (fast mode).
        """
        findings = []
        for source in source_methods:
            path = self._dfs(source, sink_descriptors, max_depth, [])
            if path:
                findings.append(path)
        return findings

    def find_all_paths(self, source_methods, sink_descriptors, max_depth=5):
        """
        Exhaustive mode: collect ALL paths (may be slow on large call graphs).
        """
        all_findings = []
        for source in source_methods:
            paths = self._dfs_all(source, sink_descriptors, max_depth, [], [])
            all_findings.extend(paths)
        return all_findings

    def _dfs(self, current_method, sinks, depth, path):
        if depth == 0:
            return None

        try:
            current_desc = f"{current_method.class_name}->{current_method.name}{current_method.descriptor}"
        except Exception:
            return None

        # Cycle guard
        if current_desc in path:
            return None

        # Check if current method is a sink
        for sink in sinks:
            if sink == "[NATIVE]":
                try:
                    flags = current_method.get_method().get_access_flags_string()
                    if "native" in flags:
                        return path + [f"{current_desc} [NATIVE_JNI_SINK]"]
                except Exception:
                    pass
            elif sink in current_desc:
                return path + [current_desc]

        # Recurse through XREFs
        try:
            for _, m, _ in current_method.get_xref_to():
                res = self._dfs(m, sinks, depth - 1, path + [current_desc])
                if res:
                    return res
        except Exception:
            pass

        return None

    def _dfs_all(self, current_method, sinks, depth, path, results):
        if depth == 0:
            return results

        try:
            current_desc = f"{current_method.class_name}->{current_method.name}{current_method.descriptor}"
        except Exception:
            return results

        if current_desc in path:
            return results

        new_path = path + [current_desc]

        for sink in sinks:
            if sink == "[NATIVE]":
                try:
                    flags = current_method.get_method().get_access_flags_string()
                    if "native" in flags:
                        results.append(new_path + [f"{current_desc} [NATIVE_JNI_SINK]"])
                        return results
                except Exception:
                    pass
            elif sink in current_desc:
                results.append(new_path)
                return results

        try:
            for _, m, _ in current_method.get_xref_to():
                self._dfs_all(m, sinks, depth - 1, new_path, results)
        except Exception:
            pass

        return results

    def is_reachable(self, source_method, sink_descriptor, max_depth=10):
        """BFS reachability check using deque (O(1) pops) — fixed from list.pop(0)."""
        visited = set()
        queue = deque([(source_method, 0)])

        while queue:
            curr, dist = queue.popleft()   # ← FIXED: was queue.pop(0) — O(n)
            if dist > max_depth:
                continue

            try:
                curr_desc = f"{curr.class_name}->{curr.name}{curr.descriptor}"
            except Exception:
                continue

            if sink_descriptor in curr_desc:
                return True

            if curr_desc in visited:
                continue
            visited.add(curr_desc)

            try:
                for _, m, _ in curr.get_xref_to():
                    queue.append((m, dist + 1))
            except Exception:
                pass

        return False
