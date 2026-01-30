def lcg_generate(a, c, m, x0, n):
    sequence = []
    x = x0
    for _ in range(n):
        x = (a * x + c) % m
        sequence.append(x)
    return sequence

def find_period(a, c, m, x0):
    seen = {}
    x = x0
    count = 0
    while x not in seen:
        seen[x] = count
        x = (a * x + c) % m
        count += 1
    start = seen[x]
    period = count - start
    return period
