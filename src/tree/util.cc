/*
 * Copyright 2013-2015 Raphael Bost
 * Copyright 2016-2017 Pascal Berrang
 *
 * This file is part of ciphermed-forests.

 *  ciphermed-forests is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 * 
 *  ciphermed-forests is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with ciphermed-forests.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <vector>
#include <cstddef>
#include <cmath>

#include <tree/util.hh>

using namespace std;

// converts long to bits
vector<long> bitDecomp(long x, size_t n)
{
    vector<long> bits(n);
    for (size_t i = 0; i < n ; i++) {
        bits[i] = x & 1;
        x>>=1;
    }
    
    return bits;
}

// marks only the bit set in long
vector<long> bitSet(long x, size_t n)
{
    vector<long> bits(n, 0);
    bits[x] = 1;

    return bits;
}

long bitDecomp_inv(const vector<long> &bits)
{
    long x = 0;
    size_t n = bits.size();
    for (size_t i = 1; i <= n ; i++) {
        x <<= 1;
        x += bits[n-i];
    }
    return x;
}

long bitSet_inv(const vector<long> &bits)
{
    size_t n = bits.size();
    for (size_t i = 0; i < n ; i++) {
        if (bits[i] != 0) return i;
    }

    return -1;
}

long max_bits(long num)
{
    return long(ceil(log2(num))) + 1;
}