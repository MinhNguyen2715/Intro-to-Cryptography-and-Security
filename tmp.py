res = 1
for i in range(57):
    res *= (1-i/365)

print(1-res)