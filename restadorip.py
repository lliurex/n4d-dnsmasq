import sys
a = sys.argv[1]
b = sys.argv[2]
list_a = a.split('.')
list_a.reverse()
list_b = b.split('.')
list_b.reverse()
total = 0
for i in range(len(list_a)):
	if i > 0 :
		total += (int(list_b[i]) - int(list_a[i])) * (256 ** i)
	else:
		total += int(list_b[i]) - int(list_a[i]) + 1
print (total)
