int main()
{
	double x;//[4] = {1.1, 1.2, 1.3, 1.4};
	unsigned long n;
        unsigned char *p;

	scanf("%lx", &n);
        p = &x;
        for(int i=0; i<8;i++)
	    p[i] = ((unsigned char*)&n)[i];

        printf("%.100e\n", x);
}

