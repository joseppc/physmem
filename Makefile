
physmem-file: physmem-file.c get_phys_addr.c test-app.c
	gcc -o $@ $^
