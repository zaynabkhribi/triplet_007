from app.decision.config import DecisionPolicies


def compatible(left: dict, right: dict) -> bool:
    return (
        left["incident_id"] != right["incident_id"]
        and left["actuator_id"] != right["actuator_id"]
        and left["id"] not in right["conflicts"]
        and right["id"] not in left["conflicts"]
    )


def verify(selected: list[dict], available: list[dict], policy: DecisionPolicies) -> bool:
    if len(selected) > policy.optimization.max_actions:
        return False
    if len({item["candidate_id"] for item in selected}) != len(selected):
        return False
    if any(item not in available for item in selected):
        return False
    if any(
        not compatible(left, right)
        for i, left in enumerate(selected)
        for right in selected[i + 1 :]
    ):
        return False
    return all(
        sum(item["resources"].get(name, 0) for item in selected) <= resource.capacity
        for name, resource in policy.resources.items()
    )


def optimize(available: list[dict], policy: DecisionPolicies) -> tuple[list[dict], str]:
    if len(available) > policy.optimization.max_candidates:
        return [], "candidate_limit_exceeded"
    if not available:
        return [], "no_authorized_candidates"
    try:
        from ortools.sat.python import cp_model

        model = cp_model.CpModel()
        choices = [model.new_bool_var(str(i)) for i in range(len(available))]
        model.add(sum(choices) <= policy.optimization.max_actions)
        for name, resource in policy.resources.items():
            model.add(
                sum(
                    item["resources"].get(name, 0) * choice
                    for item, choice in zip(available, choices, strict=True)
                )
                <= resource.capacity
            )
        for i, left in enumerate(available):
            for j in range(i + 1, len(available)):
                if not compatible(left, available[j]):
                    model.add(choices[i] + choices[j] <= 1)
        scale = len(available) * (len(available) + 1) + 1
        model.maximize(
            sum(
                (item["score"] * scale + len(available) - i) * choices[i]
                for i, item in enumerate(available)
            )
        )
        solver = cp_model.CpSolver()
        solver.parameters.max_time_in_seconds = policy.optimization.timeout_seconds
        solver.parameters.num_search_workers = 1
        solver.parameters.random_seed = 0
        status = solver.solve(model)
        if status != cp_model.OPTIMAL:
            return [], "solver_did_not_prove_optimality"
        selected = [
            item for item, choice in zip(available, choices, strict=True) if solver.value(choice)
        ]
        if not verify(selected, available, policy):
            return [], "solver_result_invalid"
        if not selected:
            return [], "constraints_require_no_action"
        return selected, "optimal_verified"
    except Exception:
        return [], "solver_unavailable_or_failed"
