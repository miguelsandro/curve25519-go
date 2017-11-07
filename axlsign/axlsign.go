// Curve25519 signatures (and also key agreement)
// like in the early Axolotl.
//
// Ported to Go by Miguel Sandro Lucero. miguel.sandro@gmail.com. 2017.11.03
// You can use it under MIT or CC0 license.
//
// Curve25519 signatures idea and math by Trevor Perrin
// https://moderncrypto.org/mail-archive/curves/2014/000205.html
//
// Derived from axlsign.js written by Dmitry Chestnykh. https://github.com/wavesplatform/curve25519-js

package axlsign

import "math"

func gf(params ...[]int64) []int64 {
    r := make([]int64, 16)
	if len(params) > 0 {
		for i := 0; i < len(params[0]); i++ {
			r[i] = params[0][i]
		}
	}
    return r
}

var _0 = make([]uint8, 16)

var _9 = []uint8 { 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
                   0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                   0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
                   0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}

var gf0 = gf()

var gf1 = gf( []int64 {1} )

var _121665 = gf( []int64 {0xdb41, 1} )

var D = gf( []int64 {0x78a3, 0x1359, 0x4dca, 0x75eb,
					 0xd8ab, 0x4141, 0x0a4d, 0x0070,
					 0xe898, 0x7779, 0x4079, 0x8cc7,
					 0xfe73, 0x2b6f, 0x6cee, 0x5203} )

var D2 = gf( []int64 {0xf159, 0x26b2, 0x9b94, 0xebd6,
					  0xb156, 0x8283, 0x149a, 0x00e0,
					  0xd130, 0xeef3, 0x80f2, 0x198e,
					  0xfce7, 0x56df, 0xd9dc, 0x2406} )

var X = gf( []int64 {0xd51a, 0x8f25, 0x2d60, 0xc956,
					 0xa7b2, 0x9525, 0xc760, 0x692c,
					 0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
					 0x53fe, 0xcd6e, 0x36d3, 0x2169} )

var Y = gf( []int64 {0x6658, 0x6666, 0x6666, 0x6666,
					 0x6666, 0x6666, 0x6666, 0x6666,
					 0x6666, 0x6666, 0x6666, 0x6666,
					 0x6666, 0x6666, 0x6666, 0x6666} )

var I = gf( []int64 {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee,
					 0xe478, 0xad2f, 0x1806, 0x2f43,
					 0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
					 0xdf0b, 0x4fc1, 0x2480, 0x2b83} )

func ushr(v int) int {
	return int( uint32( v ) ) 
}

func ts64(x []uint8 , i int, h int, l int) {
  x[i]   = uint8( (h >> 24) & 0xff )
  x[i+1] = uint8( (h >> 16) & 0xff )
  x[i+2] = uint8( (h >>  8) & 0xff )
  x[i+3] = uint8( h & 0xff )
  x[i+4] = uint8( (l >> 24) & 0xff )
  x[i+5] = uint8( (l >> 16) & 0xff )
  x[i+6] = uint8 ( (l >>  8) & 0xff )
  x[i+7] = uint8( l & 0xff )
}

func vn(x []uint8, xi int, y []uint8, yi int, n int) int {
    var d uint8 = 0
    for i := 0; i < n; i++ {
        d = d | ( x[xi+i] ^ y[yi+i] )
    }
    return int( (1 & ( ushr( int(d) - 1 ) >> 8 ) ) - 1 )
}

func crypto_verify_32(x []uint8, xi int, y []uint8, yi int) int {
  return vn(x,xi,y,yi,32)
}

func set25519(r []int64, a []int64) {
	for i := 0; i < 16; i++ {
        r[i] = a[i] | 0
    }
}

func car25519(o []int64) {
    var v int64
    var c = 1
	for i := 0; i < 16; i++ {
        v = o[i] + int64(c + 65535)
        c = int( math.Floor( float64(v) / 65536.0) )
        o[i] = v - int64(c * 65536)
    }
    o[0] += int64( c-1 + 37 * (c-1) )
}

func sel25519(p []int64, q []int64, b int) {
    var t int64
    var c = int64( ^(b-1) )
    for i := 0; i < 16; i++ {
        t = c & ( p[i] ^ q[i] )
        p[i] = p[i] ^ t
        q[i] = q[i] ^ t
    }
}

func pack25519(o []uint8, n []int64) {
    var b int64
    var m = gf()
    var t = gf()

	for i := 0; i < 16; i++ {
        t[i] = n[i]
    }
    car25519(t)
    car25519(t)
    car25519(t)

	for c := 0; c < 2; c++ {
        m[0] = t[0] - 0xffed
		for i := 1; i < 15; i++ {
            m[i] = t[i] - 0xffff - ((m[i-1] >> 16) & 1)
            m[i-1] = m[i-1] & 0xffff
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1)
        b = (m[15] >> 16) & 1
        m[14] = m[14] & 0xffff
        sel25519(t, m, int(1-b) )
    }
        
	for i := 0; i < 16; i++ {
        o[2*i] = uint8(t[i] & 0xff )
        o[2*i+1] = uint8(t[i] >> 8 )
    }
}

func neq25519(a []int64, b []int64) int {
  var c = make([]uint8, 32)
  var d = make([]uint8, 32)
  pack25519(c, a)
  pack25519(d, b)
  return crypto_verify_32(c, 0, d, 0)
}

func par25519(a []int64) int {
  var d = make([]uint8, 32)
  pack25519(d, a)
  return int(d[0]) & 1
}

func unpack25519(o []int64, n []uint8) {
	for i := 0; i < 16; i++ {
        o[i] = int64(n[2*i]) + ( int64(n[2*i+1]) << 8)
    }
    o[15] = o[15] & 0x7fff
}

func A(o []int64, a []int64, b []int64) {
	for i := 0; i < 16; i++ {
        o[i] = a[i] + b[i]
    }
}

func Z(o []int64, a []int64, b []int64) {
	for i := 0; i < 16; i++ {
        o[i] = a[i] - b[i]
    }
}

// optimized by Miguel
func M(o []int64, a []int64, b []int64) {
  var at = make([]int64, 32)
  var ab = make([]int64, 16)

  for i := 0; i < 16; i++ {
      ab[i] = b[i]
  }

  var v int64
  for i := 0; i < 16; i++ {
      v = a[i]
	  for j := 0; j < 16; j++ {	  
        at[j+i] += v * ab[j]
      }
  }

  for i := 0; i < 15; i++ {
      at[i] += 38 * at[i+16]
  }
  // t15 left as is

  // first car
  var c int64 = 1
  for i := 0; i < 16; i++ {	  
      v = at[i] + c + 65535
      c = int64( math.Floor(float64(v) / 65536.0) )
      at[i] = v - c * 65536
  }
  at[0] += c-1 + 37 * (c-1)

  // second car
  c = 1
  for i := 0; i < 16; i++ {	 
      v = at[i] + c + 65535
      c = int64( math.Floor(float64(v) / 65536.0) )
      at[i] = v - c * 65536
  }
  at[0] += c-1 + 37 * (c-1)

  for i := 0; i < 16; i++ {	  
      o[i] = at[i]
  }

}

func S(o []int64, a []int64) {
    M(o, a, a)
}

func inv25519(o []int64, i []int64) {
    var c = gf()
	for a := 0; a < 16; a++ {	
        c[a] = i[a]
    }

	for a := 253; a >= 0; a-- {
        S(c, c)
        if(a != 2 && a != 4) {
            M(c, c, i)
        }
    }
	for a := 0; a < 16; a++ {	
        o[a] = c[a]
    }
}

func pow2523(o []int64, i []int64) {
    var c = gf()
	for a := 0; a < 16; a++ {	
        c[a] = i[a]
    }
	for a := 250; a >= 0; a-- {	
        S(c, c)
        if(a != 1) {
            M(c, c, i)
        }
    }
	for a := 0; a < 16; a++ {	
        o[a] = c[a]
    }
}

func crypto_scalarmult(q []uint8, n []uint8, p []uint8) int {
    var z = make([]uint8, 32)
    var x = make([]int64, 80)
    var r int

    var a = gf()
    var b = gf()
    var c = gf()
    var d = gf()
    var e = gf()
    var f = gf()

	for i := 0; i < 31; i++ {	
        z[i] = n[i]
    }
    z[31] = (n[31] & 127) | 64
    z[0] = z[0] & 248
    
    unpack25519(x,p)
    
	for i := 0; i < 16; i++ {	
        b[i] = x[i]
        d[i] = 0
        a[i] = 0
        c[i] = 0
    }
    a[0] = 1
    d[0] = 1

    for i := 254; i >= 0; i-- {       
		r = int( ( ( z[i >> uint(3) ] ) >> uint(i & 7) ) & 1 )         
		
        sel25519(a,b,r)
        sel25519(c,d,r)

        A(e,a,c)
        Z(a,a,c)
        A(c,b,d)
        Z(b,b,d)
        S(d,e)
        S(f,a)
        M(a,c,a)
        M(c,b,e)
        A(e,a,c)
        Z(a,a,c)
        S(b,a)
        Z(c,d,f)

        M(a,c,_121665)
        A(a,a,d)
        M(c,c,a)
        M(a,d,f)
        M(d,b,x)
        S(b,e)

        sel25519(a,b,r)
        sel25519(c,d,r)

    }

	for i :=0; i<16; i++ {
        x[i+16]=a[i]
        x[i+32]=c[i]
        x[i+48]=b[i]
        x[i+64]=d[i]
    }

	var x32 = x[32:]
	var x16 = x[16:]
	
    inv25519(x32,x32)
    
    M(x16,x16,x32)

    pack25519(q,x16)

    return 0
}

func crypto_scalarmult_base(q []uint8, n []uint8) int {
  return crypto_scalarmult(q, n, _9)
}

// Constantes de cada ronda del SHA-512
var K = []int64 {
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd,
  0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
  0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
  0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
  0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe,
  0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1,
  0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
  0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
  0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
  0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483,
  0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210,
  0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
  0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
  0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
  0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926,
  0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8,
  0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
  0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
  0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
  0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910,
  0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53,
  0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
  0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
  0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
  0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60,
  0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9,
  0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
  0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
  0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
  0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6,
  0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
  0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493,
  0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
  0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
  0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817}

// optimized by miguel
func crypto_hashblocks_hl(hh []int, hl []int, m []uint8, _n int) int {

    var wh = make([]int, 16)
    var wl = make([]int, 16)

    var bh = make([]int, 8) 
    var bl = make([]int, 8) 

    var th  int
    var tl int
    var h int
    var l int
    var a int
    var b int
    var c int
    var d int

    var ah = make([]int, 8) 
    var al = make([]int, 8) 
	for i := 0; i<8; i++ {
        ah[i] = hh[i]
        al[i] = hl[i]
    }

    var pos = 0
    var n = _n
    for n >= 128 {

        for i := 0; i < 16; i++ {
          var j = 8 * i + pos
          wh[i] = (int(m[j+0]) << 24) | (int(m[j+1]) << 16) | (int(m[j+2]) << 8) | int(m[j+3]) 
          wl[i] = (int(m[j+4]) << 24) | (int(m[j+5]) << 16) | (int(m[j+6]) << 8) | int(m[j+7]) 
        }

		for i := 0; i < 80; i++ {
          for j := 0; j<7; j++ {
            bh[j] = ah[j]
            bl[j] = al[j]
          }

          // add
          h = ah[7]
          l = al[7]

          a = l & 0xffff; b = ushr(l) >> 16
          c = h & 0xffff; d = ushr(h) >> 16

          // Sigma1
          h = (( ushr(ah[4]) >> 14) | (al[4] << (32-14))) ^ (( ushr(ah[4]) >> 18) | (al[4] << (32-18))) ^ (( ushr(al[4]) >> (41-32)) | (ah[4] << (32-(41-32))))
          l = (( ushr(al[4]) >> 14) | (ah[4] << (32-14))) ^ (( ushr(al[4]) >> 18) | (ah[4] << (32-18))) ^ (( ushr(ah[4]) >> (41-32)) | (al[4] << (32-(41-32))))

          a += l & 0xffff
          b += ushr(l) >> 16
          c += h & 0xffff
          d += ushr(h) >> 16

          // Ch
          h = (ah[4] & ah[5]) ^ (^ah[4] & ah[6])
          l = (al[4] & al[5]) ^ (^al[4] & al[6])

          a += l & 0xffff; b += ushr(l) >> 16
          c += h & 0xffff; d += ushr(h) >> 16

          // K
          h = int( int32( K[i*2] ) )
          l = int( int32( K[i*2+1] ) )

          a += l & 0xffff
          b += ushr(l) >> 16
          c += h & 0xffff
          d += ushr(h) >> 16

          // w
          h = wh[i%16]
          l = wl[i%16]

          a += l & 0xffff
          b += ushr(l) >> 16
          c += h & 0xffff
          d += ushr(h) >> 16

          b += ushr(a) >> 16
          c += ushr(b) >> 16
          d += ushr(c) >> 16

          // *** R
          // th = c & 0xffff | ( d << 16 )
          // tl = a & 0xffff | ( b << 16 )
          th = c & 0xffff | d << 16
          tl = a & 0xffff | b << 16

          // add
          h = th
          l = tl

          a = l & 0xffff
          b = ushr(l) >> 16
          c = h & 0xffff
          d = ushr(h) >> 16

          // Sigma0
          h = (( ushr(ah[0]) >> 28) | (al[0] << (32-28))) ^ (( ushr(al[0]) >> (34-32)) | (ah[0] << (32-(34-32)))) ^ (( ushr(al[0]) >> (39-32)) | (ah[0] << (32-(39-32))))
          l = (( ushr(al[0]) >> 28) | (ah[0] << (32-28))) ^ (( ushr(ah[0]) >> (34-32)) | (al[0] << (32-(34-32)))) ^ (( ushr(ah[0]) >> (39-32)) | (al[0] << (32-(39-32))))

          a += l & 0xffff
          b += ushr(l) >> 16
          c += h & 0xffff
          d += ushr(h) >> 16

          // Maj
          h = (ah[0] & ah[1]) ^ (ah[0] & ah[2]) ^ (ah[1] & ah[2])
          l = (al[0] & al[1]) ^ (al[0] & al[2]) ^ (al[1] & al[2])

          a += l & 0xffff; b += ushr(l) >> 16
          c += h & 0xffff; d += ushr(h) >> 16

          b += ushr(a) >> 16
          c += ushr(b) >> 16
          d += ushr(c) >> 16

          bh[7] = (c & 0xffff) | (d << 16)
          bl[7] = (a & 0xffff) | (b << 16)

          // add
          h = bh[3]
          l = bl[3]

          a = l & 0xffff
          b = ushr(l) >> 16
          c = h & 0xffff
          d = ushr(h) >> 16

          h = th
          l = tl

          a += l & 0xffff
          b += ushr(l) >> 16
          c += h & 0xffff
          d += ushr(h) >> 16

          b += ushr(a) >> 16
          c += ushr(b) >> 16
          d += ushr(c) >> 16

          bh[3] = (c & 0xffff) | (d << 16)
          bl[3] = (a & 0xffff) | (b << 16)

          for j := 0; j<8; j++ {
              var k = ( j + 1 ) % 8
              ah[k] = bh[j]
              al[k] = bl[j]
          }

          if (i % 16 == 15) {
            for j := 0; j<16; j++ {
              // add
              h = wh[j]
              l = wl[j]

              a = l & 0xffff; b = ushr(l) >> 16
              c = h & 0xffff; d = ushr(h) >> 16

              h = wh[(j+9)%16]
              l = wl[(j+9)%16]

              a += l & 0xffff; b += ushr(l) >> 16
              c += h & 0xffff; d += ushr(h) >> 16

              // sigma0
              th = wh[(j+1)%16]
              tl = wl[(j+1)%16]

              h = (( ushr(th) >> 1) | (tl << (32-1))) ^ (( ushr(th) >> 8) | (tl << (32-8))) ^ ( ushr(th) >> 7)
              l = (( ushr(tl) >> 1) | (th << (32-1))) ^ (( ushr(tl) >> 8) | (th << (32-8))) ^ (( ushr(tl) >> 7) | (th << (32-7)))

              a += l & 0xffff; b += ushr(l) >> 16
              c += h & 0xffff; d += ushr(h) >> 16

              // sigma1
              th = wh[(j+14)%16]
              tl = wl[(j+14)%16]

              h = (( ushr(th) >> 19) | (tl << (32-19))) ^ (( ushr(tl) >> (61-32)) | (th << (32-(61-32)))) ^ ( ushr(th) >> 6)
              l = (( ushr(tl) >> 19) | (th << (32-19))) ^ (( ushr(th) >> (61-32)) | (tl << (32-(61-32)))) ^ (( ushr(tl) >> 6) | (th << (32-6)))

              a += l & 0xffff; b += ushr(l) >> 16
              c += h & 0xffff; d += ushr(h) >> 16

              b += ushr(a) >> 16
              c += ushr(b) >> 16
              d += ushr(c) >> 16

              wh[j] = ( (c & 0xffff) | (d << 16) )
              wl[j] = ( (a & 0xffff) | (b << 16) )
            }
          }
        }

        // add
        a = 0; b = 0; c = 0; d = 0
        for k := 0; k<8; k++ {
            if( k == 0 ) {
                h = ah[0]
                l = al[0]
                a = l & 0xffff; b = ushr(l) >> 16
                c = h & 0xffff; d = ushr(h) >> 16
            }

            h = hh[k]
            l = hl[k]

            a += l & 0xffff; b += ushr(l) >> 16
            c += h & 0xffff; d += ushr(h) >> 16

            b += ushr(a) >> 16
            c += ushr(b) >> 16
            d += ushr(c) >> 16

            hh[k] = (c & 0xffff) | (d << 16)
            ah[k] = (c & 0xffff) | (d << 16)

            hl[k] = (a & 0xffff) | (b << 16)
            al[k] = (a & 0xffff) | (b << 16)

            if( k < 7 ) {
                h = ah[k+1]
                l = al[k+1]

                a = l & 0xffff; b = ushr(l) >> 16
                c = h & 0xffff; d = ushr(h) >> 16
            }
		}
		
        pos += 128
        n -= 128
      }

      return n
}

var _HH = []int64 {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
var _HL = []int64 {0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1, 0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179}

func toIntArray(o []int64) []int {
    var v = make([]int, len(o))
    for i := 0; i < len(o); i++ { 
        v[i] = int(int32( o[i] ) )
        // v[i] = int( o[i] )
    }
    return v
}

func crypto_hash(out []uint8,  m []uint8, _n int) int {
    var hh = toIntArray( _HH )
    var hl = toIntArray( _HL )    
    var x = make([]uint8, 256) 
    var  n = _n
    var b = n
            
    crypto_hashblocks_hl(hh, hl, m, n)
    
    n %= 128
    
    for i := 0; i<n; i++ { 
        x[i] = m[b-n+i]
    }
    x[n] = 128

    if( n<112 ) {
        n = 256-128 * 1
    } else {
        n = 256-128 * 0
    }
    x[n-9] = 0

    ts64(x, n-8, ((b / 0x20000000) | 0), (b << 3) )

    crypto_hashblocks_hl(hh, hl, x, n)

    for i := 0; i < 8; i++ { 
        ts64(out, 8*i, hh[i], hl[i])
    }

    return 0

}

func add(p [][]int64, q [][]int64) {
    var a = gf()
    var b = gf()
    var c = gf()
    var d = gf()
    var e = gf()
    var f = gf()
    var g = gf()
    var h = gf()
    var t = gf()

    Z(a, p[1], p[0])
    Z(t, q[1], q[0])
    M(a, a, t)
    A(b, p[0], p[1])
    A(t, q[0], q[1])
    M(b, b, t)
    M(c, p[3], q[3])
    M(c, c, D2)
    M(d, p[2], q[2])
    A(d, d, d)
    Z(e, b, a)
    Z(f, d, c)
    A(g, d, c)
    A(h, b, a)

    M(p[0], e, f)
    M(p[1], h, g)
    M(p[2], g, f)
    M(p[3], e, h)
}

func cswap(p [][]int64, q [][]int64, b int) {
  for i := 0; i < 4; i++ { 
    sel25519(p[i], q[i], b)
  }
}

func pack(r []uint8, p [][]int64) {
  var tx = gf()
  var ty = gf()
  var zi = gf()

  inv25519(zi, p[2])

  M(tx, p[0], zi)
  M(ty, p[1], zi)

  pack25519(r, ty)

  r[31] = r[31] ^ uint8( par25519(tx) << 7 )

}

func scalarmult(p [][]int64, q [][]int64, s []uint8) {
    var b int

    set25519(p[0], gf0)
    set25519(p[1], gf1)
    set25519(p[2], gf1)
    set25519(p[3], gf0)

    for i := 255; i >= 0; i-- { 
        b = int( s[(i/8)|0] >> uint8( i & 7 ) ) & 1;
        cswap(p, q, b)
        add(q, p)
        add(p, p)
        cswap(p, q, b)
    }
}

func scalarbase(p [][]int64, s []uint8) {
  var q = [][]int64 {gf(), gf(), gf(), gf()}
  set25519(q[0], X)
  set25519(q[1], Y)
  set25519(q[2], gf1)
  M(q[3], X, Y)
  scalarmult(p, q, s)
}

var L = []int64 { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 }

func modL(r []uint8, x []int64) {

  var carry int64

  for i := 63; i >= 32; i-- { 
    carry = 0
    var j = i - 32
    var k = i - 12
    for j < k {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)]
      carry = (x[j] + 128) >> 8
      x[j] -= carry * 256
      j += 1
    }
    x[j] += carry
    x[i] = 0
  }

  carry = 0
  for j := 0; j<32; j++ {
    x[j] += carry - (x[31] >> 4) * L[j]
    carry = x[j] >> 8
    x[j] = x[j] & 255
  }

  for j := 0; j<32; j++ {
    x[j] -= carry * L[j]
  }

  for i := 0; i < 32; i++ { 
    x[i+1] += x[i] >> 8
    r[i] = uint8( x[i] & 255 ) 
  }

}

func reduce(r []uint8) {
  var x = make([]int64, 64) 
  for i := 0; i < 64; i++ { 
    x[i] = int64( r[i] ) 
  }
  for i := 0; i < 64; i++ { 
    r[i] = 0
  }
  modL(r, x)
}

// Like crypto_sign, but uses secret key directly in hash.
func crypto_sign_direct(sm []uint8, m []uint8, n int, sk []uint8) int {
  var h = make([]uint8, 64) 
  var r = make([]uint8, 64) 
  var x = make([]int64, 64) 
  var p = [][]int64 {gf(), gf(), gf(), gf()}

  for i := 0; i < n; i++ { 
    sm[64 + i] = m[i]
  }

  for i := 0; i < 32; i++ { 
    sm[32 + i] = sk[i]
  }

  crypto_hash(r, sm[32:], n+32)
  
  reduce(r)

  scalarbase(p, r)

  pack(sm, p)

  for i := 0; i < 32; i++ { 
    sm[i + 32] = sk[32 + i]
  }

  crypto_hash(h, sm, n + 64)
  reduce(h)

  for i := 0; i < 64; i++ { 
    x[i] = 0
  }

  for i := 0; i < 32; i++ { 
    x[i] = int64(r[i]) 
  }

  for i := 0; i < 32; i++ { 
    for j :=0; j<32; j++ {
      x[i+j] += int64( h[i] ) * int64( sk[j] )
    }
  }

  var tmp = sm[32:]
  modL(tmp, x)
  for i := 0; i < len(tmp); i++ { 
    sm[32+i] = tmp[i]
  }

  return n + 64

}

// Note: sm must be n+128.
func crypto_sign_direct_rnd(sm []uint8, m []uint8, n int, sk []uint8, rnd []uint8) int {
  var h = make([]uint8, 64) 
  var r = make([]uint8, 64) 
  var x = make([]int64, 64) 
  var p = [][]int64 {gf(), gf(), gf(), gf()}

  // Hash separation.
  sm[0] = 0xfe
  for i := 1; i < 32; i++ { 
    sm[i] = 0xff
  }

  // Secret key.
  for i := 0; i < 32; i++ { 
    sm[32 + i] = sk[i]
  }

  // Message.
  for i := 0; i < n; i++ { 
    sm[64 + i] = m[i]
  }

  // Random suffix.
  for i := 0; i < 64; i++ { 
    sm[n + 64 + i] = rnd[i]
  }
  
  crypto_hash(r, sm, n+128)
  
  reduce(r)
  scalarbase(p, r)
  pack(sm, p)

  for i := 0; i < 32; i++ { 
    sm[i + 32] = sk[32 + i]
  }

  crypto_hash(h, sm, n + 64)
  reduce(h)
  
  // Wipe out random suffix.
  for i := 0; i < 64; i++ { 
    sm[n + 64 + i] = 0
  }

  for i := 0; i < 64; i++ { 
    x[i] = 0
  }

  for i := 0; i < 32; i++ { 
    x[i] = int64( r[i] ) 
  }

  for i := 0; i < 32; i++ { 
    for j := 0; j<32; j++ {
      x[i+j] += int64( h[i] ) * int64( sk[j] ) 
    }
  }

  var tmp = sm[32:] 
  modL(tmp, x)
  for i := 0; i < len(tmp); i++ { 
    sm[32+i] = tmp[i]
  }

  return n + 64
}

func curve25519_sign(sm []uint8, m []uint8, n int, sk []uint8, opt_rnd []uint8) int {
  // If opt_rnd is provided, sm must have n + 128,
  // otherwise it must have n + 64 bytes.

  // Convert Curve25519 secret key into Ed25519 secret key (includes pub key).
  var edsk = make([]uint8, 64) 
  var p = [][]int64 {gf(), gf(), gf(), gf()}

  for i := 0; i < 32; i++ { 
    edsk[i] = sk[i]
  }

  // Ensure key is in the correct format.
  edsk[0] = edsk[0] & 248
  edsk[31] = edsk[31] & 127
  edsk[31] = edsk[31] | 64

  scalarbase(p, edsk)
      
  var tmp = edsk[32:] 
  pack(tmp, p)
  for i := 0; i < len(tmp); i++ { 
    edsk[32+i] = tmp[i]
  }
  
  // Remember sign bit.
  var signBit = edsk[63] & 128
  var smlen int

  if (opt_rnd == nil ) {
    smlen = crypto_sign_direct(sm, m, n, edsk)    
  } else {
	smlen = crypto_sign_direct_rnd(sm, m, n, edsk, opt_rnd)    
  }

  // Copy sign bit from public key into signature.
  sm[63] = sm[63] | signBit
    
  return smlen
}

func unpackneg(r [][]int64, p []uint8) int {
  var t = gf()
  var chk = gf()
  var num = gf()
  var den = gf()
  var den2 = gf()
  var den4 = gf()
  var den6 = gf()

  set25519(r[2], gf1)
  unpack25519(r[1], p)

  S(num, r[1])
  M(den, num, D)
  Z(num, num, r[2])
  A(den, r[2], den)

  S(den2, den)
  S(den4, den2)
  M(den6, den4, den2)
  M(t, den6, num)
  M(t, t, den)

  pow2523(t, t)
  M(t, t, num)
  M(t, t, den)
  M(t, t, den)
  M(r[0], t, den)

  S(chk, r[0])
  M(chk, chk, den)

  if ( neq25519(chk, num) != 0 ) {
    M(r[0], r[0], I)
  }

  S(chk, r[0])
  M(chk, chk, den)

  if ( neq25519(chk, num) != 0 ) {
    return -1
  }

  if ( par25519(r[0]) == (int(p[31]) >> 7) ) { 
    Z(r[0], gf0, r[0])
  }

  M(r[3], r[0], r[1])

  return 0
}

func crypto_sign_open(m []uint8, sm []uint8, _n int, pk []uint8) int {
  var t = make([]uint8, 32) 
  var h = make([]uint8, 64) 
  var p = [][]int64 {gf(), gf(), gf(), gf()}
  var q = [][]int64 {gf(), gf(), gf(), gf()}
  var n = _n

  var mlen = -1
  if (n < 64) {
    return mlen
  }

  if ( unpackneg(q, pk) != 0 ) {
    return mlen
  }

  for i := 0; i < n; i++ { 
    m[i] = sm[i]
  }

  for i := 0; i < 32; i++ { 
    m[i+32] = pk[i]
  }

  crypto_hash(h, m, n)

  reduce(h)
  scalarmult(p, q, h)

  scalarbase(q, sm[32:]); 
  add(p, q)
  pack(t, p)

  n -= 64
  if ( crypto_verify_32(sm, 0, t, 0) != 0 ) {
    for i := 0; i < n; i++ { 
      m[i] = 0
    }
    return -1
  }

  for i := 0; i < n; i++ { 
    m[i] = sm[i + 64]
  }

  mlen = n
  return mlen

}

// Converts Curve25519 public key back to Ed25519 public key.
// edwardsY = (montgomeryX - 1) / (montgomeryX + 1)
func convertPublicKey(pk []uint8) []uint8 {
  var z = make([]uint8, 32) 
  var x = gf()
  var a = gf()
  var b = gf()

  unpack25519(x, pk)

  A(a, x, gf1)
  Z(b, x, gf1)
  inv25519(a, a)
  M(a, a, b)

  pack25519(z, a)
  return z
}

func curve25519_sign_open(m []uint8, sm []uint8, n int, pk []uint8) int {
  // Convert Curve25519 public key into Ed25519 public key.
  var edpk = convertPublicKey(pk)

  // Restore sign bit from signature.
  edpk[31] = edpk[31] | ( sm[63] & 128)

  // Remove sign bit from signature.
  var _sm = sm[:] 

  _sm[63] = _sm[63] & 127

  // Verify signed message.
  return crypto_sign_open(m, _sm, n, edpk)
}

/* AxlSign */

func SharedKey(secretKey []uint8, publicKey []uint8) []uint8 {
  var sharedKey = make([]uint8, 32) 
  crypto_scalarmult(sharedKey, secretKey, publicKey)
  return sharedKey
}

func SignMessage(secretKey []uint8, msg []uint8, opt_random  []uint8) []uint8 {
  if (opt_random != nil ) {
	var buf = make([]uint8, 128 + len(msg)) 
	curve25519_sign(buf, msg, len(msg), secretKey, opt_random)
	return buf[0:64 + len(msg)] 
  } else {
	var signedMsg = make([]uint8, 64 + len(msg)) 
	curve25519_sign(signedMsg, msg, len(msg), secretKey, nil)
	return signedMsg
  }
}
 
func OpenMessage(publicKey []uint8, signedMsg []uint8) []uint8 {
  var tmp = make([]uint8, len(signedMsg) ) 
  var mlen = curve25519_sign_open(tmp, signedMsg, len(signedMsg), publicKey)
  if (mlen < 0) {
	return nil
  }
  var m = make([]uint8, mlen) 
  for i := 0; i < len(m); i++ { 
	m[i] = tmp[i]
  }
  return m
}

// add by Miguel
func OpenMessageStr(publicKey []uint8, signedMsg []uint8) string {
	var m = OpenMessage(publicKey, signedMsg)
	return string(m)
}

func Sign(secretKey []uint8, msg []uint8, opt_random []uint8 ) []uint8 {
  var _len = 64
  if (opt_random != nil) {
	_len = 128
  }
  var buf = make([]uint8, _len + len(msg))
  
  curve25519_sign(buf, msg, len(msg), secretKey, opt_random)

  var signature = make([]uint8, 64 ) 
  for i := 0; i < len(signature); i++ { 
	signature[i] = buf[i]
  }
  return signature
}

func Verify(publicKey []uint8, msg []uint8, signature []uint8) int {
  var sm = make([]uint8, 64 + len(msg) ) 
  var m = make([]uint8, 64 + len(msg) ) 

  for i := 0; i < 64; i++ { 
	sm[i] = signature[i]
  }

  for i := 0; i < len(msg); i++ { 
	sm[i+64] = msg[i]
  }

  if ( curve25519_sign_open(m, sm, len(sm), publicKey) >= 0 ) {
	return 1
  } else {
	return 0
  }
}

type Keys struct {
	PublicKey []uint8
    PrivateKey []uint8
}

func GenerateKeyPair(seed []uint8) Keys {
  var sk = make([]uint8, 32 ) 
  var pk = make([]uint8, 32 ) 

  for i := 0; i < 32; i++ { 
	sk[i] = seed[i]
  }

  crypto_scalarmult_base(pk, sk)

  // Turn secret key into the correct format.
  sk[0] = sk[0] & 248
  sk[31] = sk[31] & 127
  sk[31] = sk[31] | 64

  // Remove sign bit from public key.
  pk[31] = pk[31] & 127

  return Keys {pk, sk}

}

/*
func debugA8(t string, a []uint8) {
	fmt.Printf(t + " [%d] ", len(a))
	var sum = 0
	for i := 0; i< len(a); i++ {
		sum += int(a[i])
		fmt.Printf("%d ", a[i])
	}
	fmt.Printf(" - suma: %d\n\n", sum)
}
*/
