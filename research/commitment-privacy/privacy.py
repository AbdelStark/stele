"""Q29 exact finite-field linear views; research helpers, never protocol authority."""


def rank(matrix, p):
    rows = [[v % p for v in row] for row in matrix]
    if not rows:
        return 0
    assert all(len(row) == len(rows[0]) for row in rows)
    at = 0
    for column in range(len(rows[0])):
        pivot = next((i for i in range(at,len(rows)) if rows[i][column]), None)
        if pivot is None:
            continue
        rows[at], rows[pivot] = rows[pivot], rows[at]
        inverse = pow(rows[at][column], -1, p)
        rows[at] = [v*inverse % p for v in rows[at]]
        for i in range(at+1,len(rows)):
            scale = rows[i][column]
            rows[i] = [(a-scale*b) % p for a,b in zip(rows[i],rows[at])]
        at += 1
    return at


def private(secret_map, mask_map, p):
    assert len(secret_map) == len(mask_map)
    combined = [list(b)+list(a) for a,b in zip(secret_map,mask_map)]
    return rank(combined,p) == rank(mask_map,p)


def observe(secret_map, mask_map, secret, mask, p):
    assert len(secret_map) == len(mask_map)
    assert all(len(a) == len(secret) and len(b) == len(mask) for a,b in zip(secret_map,mask_map))
    return tuple((sum(v*x for v,x in zip(a,secret))+sum(v*r for v,r in zip(b,mask))) % p
                 for a,b in zip(secret_map,mask_map))


def randomized_row(secret, message_points, mask, queries, p):
    assert len(secret) == len(message_points) > 0
    assert len(set(t % p for t in message_points)) == len(message_points)
    result = []
    for q in queries:
        value, vanishing = 0, 1
        for i,z in enumerate(message_points):
            numerator = denominator = 1
            for j,other in enumerate(message_points):
                if i != j:
                    numerator = numerator*(q-other) % p
                    denominator = denominator*(z-other) % p
            value = (value+secret[i]*numerator*pow(denominator,-1,p)) % p
            vanishing = vanishing*(q-z) % p
        random = 0
        for coefficient in reversed(mask):
            random = (random*q+coefficient) % p
        result.append((value+vanishing*random) % p)
    return tuple(result)
