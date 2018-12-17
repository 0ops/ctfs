/*************************************************************************
	> File Name: map.cpp
	> Author: 
	> Mail: 
	> Created Time: Fri Jul  6 14:32:47 2018
 ************************************************************************/

#include<iostream>
#include<cstdlib>
#include<map>
#include<gmp.h>
#define ll long long unsigned
using namespace std;

mpz_t mod, n;

ll inv(ll a)
{
    mpz_t tmp;
    mpz_init(tmp);
    mpz_set_ui(tmp, a);
    mpz_invert(tmp, tmp, mod);
    mpz_mul(tmp, tmp, n);
    mpz_mod(tmp, tmp, mod);
    
    ll res = mpz_get_ui(tmp);
    mpz_clear(tmp);
    return res;
}

int main()
{
    mpz_init_set_str(mod, "0x10000000000000000", 0);
    mpz_init_set_str(n  , "0x0bdd05cc7fef2c91f", 0);

    map<ll, unsigned> m;
    unsigned cnt = 0;
    ll tmp = 0;
    FILE *fp = fopen("rec", "rb");
    while (fread(&tmp, 8, 1, fp) == 1)
    {
        if ((cnt & 0xfffff) == 0)
            cout << hex << cnt << endl;
        ++cnt;
        if (tmp % 2 == 0)
            continue;
	// if (cnt > 20)
	//     break;
        m[tmp] = cnt;
	// cout << hex << tmp << ' ' << cnt << endl;
    }
    fclose(fp);
    cout << "Table OK!" << endl;

    fp = fopen("inv", "rb");
    tmp = 0;
    cnt = 0;
    while (fread(&tmp, 8, 1, fp) == 1)
    {
        if ((cnt & 0xffffff) == 0)
            cout << hex << cnt << endl;
        ++cnt;
	if (tmp == 0)
            continue;
        auto pn = m.find(tmp);
        // auto pn = m.find(inv(tmp));
        if (pn != m.end())
        {
            cout << "!!!!!!!!!!!!!!!!!" << endl;
            cout << hex << (cnt-1) << endl; 
            cout << hex << pn->first << ' ' << pn->second << endl;
            cout << "!!!!!!!!!!!!!!!!!" << endl;
        }
	// if (cnt > 20)
	//     break;
    }
    
    mpz_clear(mod);
    mpz_clear(n);
    return 0;
}
