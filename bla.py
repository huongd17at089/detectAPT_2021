# abc = {}
# abc.update({"a" : ["1","a"],
#             "b" : 2})
#
# print(abc)
#
# def test(data):
#     abc.update({"a" : 2, "b" : 3})
#
# test(abc)
# print(abc)

# from builtins import any
# lst = ['yellow', 'orange', 'red']
# word = "yellowaa"
# print(any(x in word for x in lst))

for i in range(5):
    for j in range(3):
        print(i)
        if(i== 2 and j == 1):
            break
    print("oke")
