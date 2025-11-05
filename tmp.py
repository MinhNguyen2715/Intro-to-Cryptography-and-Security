res = []
for x in [1,5,7,11]:
    print(x)
    for i in range(0,12):
        print(i, pow(x,i,12), sep=": ")

