from math import sqrt
from statistics import mean, pstdev


def statistics(points: list[tuple[float, float]], alpha: float) -> dict:
    values = [value for _, value in points]
    if not values:
        return {"count": 0, "mean": None, "stddev": None, "ema": None, "rate_per_second": None}
    ema = values[0]
    for value in values[1:]:
        ema = alpha * value + (1 - alpha) * ema
    elapsed = points[-1][0] - points[0][0]
    return {
        "count": len(values),
        "mean": mean(values),
        "stddev": pstdev(values),
        "ema": ema,
        "rate_per_second": (values[-1] - values[0]) / elapsed if elapsed > 0 else None,
    }


def correlation(left: dict[float, float], right: dict[float, float]) -> float | None:
    times = sorted(left.keys() & right.keys())
    if len(times) < 2:
        return None
    xs, ys = [left[t] for t in times], [right[t] for t in times]
    dx, dy = [x - mean(xs) for x in xs], [y - mean(ys) for y in ys]
    denominator = sqrt(sum(x * x for x in dx) * sum(y * y for y in dy))
    return sum(x * y for x, y in zip(dx, dy, strict=True)) / denominator if denominator else None
