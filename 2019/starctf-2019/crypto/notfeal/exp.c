#include <stdlib.h>
#include <stdio.h>
#include <math.h>

unsigned long subkey[6] = {66051, 16909060, 33752069, 50595078, 67438087, 84281096};

unsigned long long shiftLeft2(unsigned long a){
    unsigned long b;

    unsigned long carry = (a >> 7LL);
    carry &= 0x1LL;
    b = a << 1LL;
    b += carry;
    b &= 0xFFLL;

    carry = (b >> 7LL);
    carry &= 0x1LL;
    b <<= 1LL;
    b += carry;
    b &= 0xFFLL;

    return b;
}

unsigned long gBox(unsigned long a, unsigned long b, unsigned long mode){
    return shiftLeft2((a + b + mode) % 256LL);
}

unsigned long fBox(unsigned long plain){
    unsigned long x3 = plain & 0xFFL;
    unsigned long x2 = (plain >> 8L) & 0xFFL;
    unsigned long x1 = (plain >> 16L) & 0xFFL;
    unsigned long x0 = (plain >> 24L) & 0xFFL;

    unsigned long t0 = (x2 ^ x3);
    unsigned long t1 = gBox(x0 ^ x1, t0, 1L);

    unsigned long y0 = gBox(x0, t1, 0L);
    unsigned long y1 = t1;
    unsigned long y2 = gBox(t0, t1, 0L);
    unsigned long y3 = gBox(x3, y2, 1L);

    unsigned long ret =  y3 << 24L;
                 ret += (y2 << 16L);
                 ret += (y1 << 8L);
                 ret += y0;
    return ret;
}

unsigned long long encrypt(unsigned long long plain){
    unsigned long left = (plain >> 32LL) & 0xFFFFFFFFLL;
    unsigned long right = plain & 0xFFFFFFFFLL;
    
    left = left ^ subkey[4];
    right = right ^ subkey[5]^left;
    //printf("0x%08lx 0x%08lx\n",left,right);
    for(int i=0;i<4;i++){
        unsigned long tmp = left;
        left = right^fBox(left^subkey[i]);
        right = tmp;
        //printf("%d 0x%08lx 0x%08lx\n",i,left,right);
    }
    unsigned long tmp = right;
    right = right^left;
    left = tmp;
    unsigned long long ret = (((unsigned long long)(left)) << 32LL);
    ret += (((unsigned long long)(right)) & 0xFFFFFFFFLL);
    //printf("0x%08lx 0x%08lx\n",left,right);
    return ret;
}

int numPlain;

unsigned long long plain[20] = {6355543057381347776, 11827889715377394664, 7968723713229439248, 15497420345837553209, 8073845929094533159, 16621969158629929646, 10723502874350509174, 9677942042813506846, 3808369104898565557, 13915491585670448433, 4190379625996117675, 17332101120678098711};
unsigned long long plain0[20] = {6355543057381347776, 11827889715377394664, 7968723713229439248, 15497420345837553209, 8073845929094533159, 16621969158629929646, 10723502874350509174, 9677942042813506846, 3808369104898565557, 13915491585670448433, 4190379625996117675, 17332101120678098711};
unsigned long long plain1[20] = {15614943889099215298, 2640546477680677866, 17156066955221123346, 6310077108140836411, 17333246765107367973, 7362568322600317612, 1464102042615864436, 490598805116790044, 12995712342595282359, 4728148343678764339, 13449780462008952489, 8072700284665263893};
unsigned long long plain2[20] = {15614943889099215296, 2640546477680677864, 17156066955221123344, 6310077108140836409, 17333246765107367975, 7362568322600317614, 1464102042615864438, 490598805116790046, 12995712342595282357, 4728148343678764337, 13449780462008952491, 8072700284665263895};
unsigned long long plain3[20] = {6355543065971282368, 11827889706787460072, 7968723704639504656, 15497420337247618617, 8073845937684467751, 16621969167219864238, 10723502882940443766, 9677942034223572254, 3808369113488500149, 13915491577080513841, 4190379634586052267, 17332101112088164119};
unsigned long long cipher[20] = {1648253753452016450, 8644534213661647529, 5575275532819768760, 9476506130490707488, 1910209432109438107, 11790830001168321807, 17821843297530110816, 14538625493057999772, 1508516146120046618, 3449752371070405088, 16972342112639146520, 8278607829037245296};
unsigned long long cipher0[20] = {1648253753452016450, 8644534213661647529, 5575275532819768760, 9476506130490707488, 1910209432109438107, 11790830001168321807, 17821843297530110816, 14538625493057999772, 1508516146120046618, 3449752371070405088, 16972342112639146520, 8278607829037245296};
unsigned long long cipher1[20] = {1648253745788496736, 8644534223475796683, 5575275524644560218, 9476506135409051138, 1910209423387909369, 11790829992994149868, 17821843289061288833, 14538625482993241022, 1508516155323920504, 3449752381126771074, 16972342105003926074, 8278607837217717074};
unsigned long long cipher2[20] = {5098949972688110070, 7626333810448098767, 18090606674179965230, 3665802093549233061, 3439976268065051352, 15659963536307107137, 18352670047965414903, 11515913831755533075, 1082312539903918115, 10917040575581327151, 8182606473586552194, 17196214821642791082};
unsigned long long cipher3[20] = {7085367810197478649, 15412187783494443250, 9010454056953286998, 9772887868896141806, 17768023588176534098, 3448123341270810827, 6892669051248954635, 7576698372485608419, 16120435719193783824, 2134601704660437335, 11235408719679260592, 10589080717708391722};

unsigned long long  flag0 = 1750000208663375421LL;
unsigned long long  flag1 = 11199315014381507866LL;
unsigned long long  flag2 = 3740747533449303241LL;
unsigned long long  flag3 = 209325490234655513LL;
unsigned long long  flag4 = 6397710886079583658LL;


unsigned long key5winner;
unsigned long key4winner;
unsigned long key3winner;
unsigned long key2winner;
unsigned long key1winner;
unsigned long key0winner;
unsigned long keywinner;

unsigned long long decrypt(unsigned long long enc){
    unsigned long left = (enc >> 32LL) & 0xFFFFFFFFLL;
    unsigned long right = enc & 0xFFFFFFFFLL;
    
    right = right^left;
    unsigned long tmp;

    right = fBox(left^key3winner)^right;

    tmp = right;
    right = fBox(right^key2winner)^left;
    left = tmp;

    tmp = right;
    right = fBox(right^key1winner)^left;
    left = tmp;

    tmp = right;
    right = fBox(right^key0winner)^left;
    left = tmp;

    right = left^right;
    left = left^key4winner;
    right = right^key5winner;

    unsigned long long ret = (((unsigned long long)(left)) << 32LL);
    ret += (((unsigned long long)(right)) & 0xFFFFFFFFLL);
    return ret;
}

void crackSubkey(unsigned long outdiff,int offset){
    unsigned long fakeK;
    int index = 0;
    for(fakeK = 0x00000000L; fakeK < 0xFFFFFFFFL; fakeK++){
        int score = 0;
        //if((fakeK&0xffffff)==0) printf("%x\n",fakeK);
        int c;
        for(c = 0; c < numPlain; c++){
            unsigned long fakeRight0 = cipher0[c] & 0xFFFFFFFFLL;
            unsigned long fakeRight1 = cipher1[c] & 0xFFFFFFFFLL;
            unsigned long fakeLeft0 = cipher0[c] >> 32LL;
            unsigned long fakeLeft1 = cipher1[c] >> 32LL;

            unsigned long Z0 = fBox(fakeK^fakeRight0);
            unsigned long Z1 = fBox(fakeK^fakeRight1);

            unsigned long Z = Z0 ^ Z1 ^ outdiff;
            unsigned long fakeDiff = fakeLeft0 ^ fakeLeft1;
            if (fakeDiff == Z) score++; else break;
        }

        if (score == numPlain){
            printf("DISCOVERED SUBKEY = %08lx\n", fakeK);
            keywinner = fakeK;
            index++;
            if(index==offset) break;
        }
    }
}


void crackSubkey3ULTRA(unsigned long outdiff,int offset){
    unsigned long fakeK;
    int index = 0;
    for(fakeK = 0x00000000L; fakeK < 0xFFFFFFFFL; fakeK++){
        int score = 0;
        //if((fakeK&0xffffff)==0) printf("%x\n",fakeK);
        
        int c;
        for(c = 0; c < numPlain; c++){
            unsigned long fakeRight0 = cipher0[c] & 0xFFFFFFFFLL;
            unsigned long fakeRight1 = cipher1[c] & 0xFFFFFFFFLL;
            unsigned long fakeLeft0 = cipher0[c] >> 32LL;
            unsigned long fakeLeft1 = cipher1[c] >> 32LL;

            unsigned long Z0 = fakeLeft0^fakeRight0;
            unsigned long Z1 = fakeLeft1^fakeRight1;

            unsigned long Z = Z0 ^ Z1 ^ outdiff;

            unsigned long fakeInput0 = fakeLeft0 ^ fakeK;
            unsigned long fakeInput1 = fakeLeft1 ^ fakeK;
            unsigned long fakeOut0 = fBox(fakeInput0);
            unsigned long fakeOut1 = fBox(fakeInput1);
            unsigned long fakeDiff = fakeOut0 ^ fakeOut1;

            if (fakeDiff == Z) score++; else break;
        }

        if (score == numPlain){
            printf("DISCOVERED SUBKEY = %08lx\n", fakeK);
            keywinner = fakeK;
            index++;
            if(index==offset) break;
        }
    }
}

void undoFinal(unsigned long key){
    for(int c=0;c<numPlain;c++){
        //printf("%d\n",c);
        unsigned long Right0 = cipher0[c] & 0xFFFFFFFFLL;
        unsigned long Left0 = cipher0[c] >> 32LL;
        unsigned long tmp0 = fBox(Left0^key)^Left0^Right0;
        cipher0[c] = (((unsigned long long)(Left0)) << 32LL);
        cipher0[c] += (((unsigned long long)(tmp0) & 0xFFFFFFFFLL));
        
        unsigned long Right1 = cipher1[c] & 0xFFFFFFFFLL;
        unsigned long Left1 = cipher1[c] >> 32LL;
        unsigned long tmp1 = fBox(Left1^key)^Left1^Right1;
        cipher1[c] = (((unsigned long long)(Left1)) << 32LL);
        cipher1[c] += (((unsigned long long)(tmp1)) & 0xFFFFFFFFLL);
    }
}

void undoOneRound(unsigned long key){
    for(int c=0;c<numPlain;c++){
        unsigned long Right0 = cipher0[c] & 0xFFFFFFFFLL;
        unsigned long Left0 = cipher0[c] >> 32LL;
        unsigned long tmp0 =  fBox(Right0^key)^Left0;
        cipher0[c] = (((unsigned long long)(Right0)) << 32LL);
        cipher0[c] += (((unsigned long long)(tmp0)) & 0xFFFFFFFFLL);
        
        unsigned long Right1 = cipher1[c] & 0xFFFFFFFFLL;
        unsigned long Left1 = cipher1[c] >> 32LL;
        unsigned long tmp1 =  fBox(Right1^key)^Left1;
        cipher1[c] = (((unsigned long long)(Right1)) << 32LL);
        cipher1[c] += (((unsigned long long)(tmp1)) & 0xFFFFFFFFLL);
    }
}

int main(){

    numPlain = 12;

/*
80800000 -> 00000002
00008080 -> 02000000
    for(unsigned long diff = 1;diff<=0xffffffff;diff++){
        int flag = 1;
        //if((diff&0xffffff)==0) printf("%08lx\n",diff);
        unsigned long com = fBox(0)^fBox(diff);
        for(unsigned long data = 0x1000;data<=0x10000;data+=0x1000){
            unsigned long tmp = fBox(data)^fBox(data^diff);
            if(tmp!=com){
                flag = 0;
                break;
            }
        }
        if(flag==0) continue;
        else{
            printf("%08lx -> %08lx\n",diff,com);
        }
    }*/

    unsigned long long diff1 = 0x8080000080800002LL;
    unsigned long outdiff1 = 0x80800000;
    crackSubkey3ULTRA(outdiff1,1);
    key3winner = keywinner;

    //key3winner = 0x51a2760c;

    unsigned long long diff2 = 0x8080000080800000LL;
    unsigned long outdiff2 = 0x0000002;
    for(int c=0;c<numPlain;c++){
        plain0[c] = plain[c];
        plain1[c] = plain2[c];
        cipher0[c] = cipher[c];
        cipher1[c] = cipher2[c];
    }
    undoFinal(key3winner);
    crackSubkey(outdiff2,1);
    key2winner = keywinner;

    //key2winner = 0x307e509c;

    printf("%08lx %08lx\n",key3winner,key2winner);
    unsigned long long diff3 = 0x000000200000000;
    unsigned long outdiff3 = 0x0000002;
    for(int c=0;c<numPlain;c++){
        plain0[c] = plain[c];
        plain1[c] = plain3[c];
        cipher0[c] = cipher[c];
        cipher1[c] = cipher3[c];
    }
    undoFinal(key3winner);
    undoOneRound(key2winner);
    crackSubkey(outdiff3,1);
    key1winner = keywinner;
    undoOneRound(key1winner);

    unsigned long fakeK0;
    for(fakeK0 = 0; fakeK0 < 0xFFFFFFFFL; fakeK0++){
        unsigned long fakeK4 = 0;
        unsigned long fakeK5 = 0;
        int c;
        for(c = 0; c < numPlain; c++){
            unsigned long plainLeft0 = plain0[c]>>32;
            unsigned long plainRight0 = plain0[c] & 0xFFFFFFFFLL;
            unsigned long cipherLeft0 = cipher0[c]>>32;
            unsigned long cipherRight0 = cipher0[c] & 0xFFFFFFFFLL;

            unsigned long tempy0 = fBox(cipherRight0 ^ fakeK0) ^ cipherLeft0;
            if (fakeK5 == 0){
                fakeK4 = cipherRight0 ^ plainLeft0;
                fakeK5 = tempy0 ^ cipherRight0 ^ plainRight0;
            }else if(((cipherRight0^plainLeft0)!=fakeK4)||((tempy0^cipherRight0^plainRight0)!=fakeK5)){
                fakeK4 = 0;
                fakeK5 = 0;
                break; 	 
            }
        }
        if (fakeK4 != 0){
            key0winner = fakeK0;
            key4winner = fakeK4;
            key5winner = fakeK5;
            printf("found subkeys : 0x%08lx  0x%08lx  0x%08lx\n", fakeK0, fakeK4, fakeK5);
            unsigned long long tmp0 = decrypt(flag0);
            unsigned long long tmp1 = decrypt(flag1);
            unsigned long long tmp2 = decrypt(flag2);
            unsigned long long tmp3 = decrypt(flag3);
            unsigned long long tmp4 = decrypt(flag4);
            printf("%.8s%.8s%.8s%.8s%.8s\n",&tmp4,&tmp3,&tmp2,&tmp1,&tmp0);
            break;
        }
    }
    return 0;
}