import math
from backend.generator import lcg_generate

def cesaro_test(num_samples, a, c, m, x0):
    if num_samples <= 0:
        raise ValueError("num_samples must be > 0")

    count = 0
    x = x0

    for _ in range(num_samples):
        pair = lcg_generate(a, c, m, x, 2)
        v1, v2 = pair[0], pair[1]
        x = v2

        if math.gcd(v1, v2) == 1:
            count += 1

    probability = count / num_samples
    if probability == 0:
        estimated_pi = float("inf")
    else:
        estimated_pi = math.sqrt(6 / probability)
    return estimated_pi, probability
