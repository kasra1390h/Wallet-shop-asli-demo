const test=require('node:test'),assert=require('node:assert/strict');
const {luhnOk,magicOk,sniffImage,isValidLottieJson,recipientValid,canTransition,priceCalc,toCsv,parseAdminRoles,roleHas}=require('../lib.js');

test('luhnOk accepts a real Luhn-valid card number and rejects a broken one',()=>{
 assert.equal(luhnOk('4532015112830366'),true);   // known-valid test PAN
 assert.equal(luhnOk('4532015112830367'),false);  // last digit corrupted
 assert.equal(luhnOk('0000000000000000'),true);   // all-zero passes Luhn trivially — length check is separate
});

test('magicOk validates real PNG/JPEG headers and rejects spoofed mime',()=>{
 const png=Buffer.from([0x89,0x50,0x4e,0x47,0,0,0,0,0]);
 const jpg=Buffer.from([0xff,0xd8,0xff,0xe0,0,0,0,0,0]);
 const fake=Buffer.from('not-an-image-just-text');
 assert.equal(magicOk(png,'image/png'),true);
 assert.equal(magicOk(jpg,'image/jpeg'),true);
 assert.equal(magicOk(fake,'image/png'),false);
 assert.equal(magicOk(png,'image/jpeg'),false); // real PNG bytes, but claiming to be jpeg -> reject
 assert.equal(magicOk(fake,'application/octet-stream'),false);
});

test('recipientValid enforces the username shape',()=>{
 assert.equal(recipientValid('@john_doe'),true);
 assert.equal(recipientValid('john_doe'),true);
 assert.equal(recipientValid('ab'),false); // too short
 assert.equal(recipientValid('<script>alert(1)</script>'),false);
 assert.equal(recipientValid(''),false);
});

test('order state machine allows only legal transitions',()=>{
 assert.equal(canTransition('paid','fulfilling'),true);
 assert.equal(canTransition('paid','delivered'),false);      // must go through fulfilling
 assert.equal(canTransition('delivered','processing'),false); // no such state at all
 assert.equal(canTransition('refunded','delivered'),false);  // terminal state, can't reverse
 assert.equal(canTransition('fulfilling','refunded'),true);
 assert.equal(canTransition('failed','fulfilling'),true);    // retry path
});

test('priceCalc matches the documented formula and rounds up (never undercharges)',()=>{
 // 200 stars * 1 qty * $0.014/star * 900,000 toman/$ = 2,520,000 base; 5% fee = 126,000
 const p=priceCalc(200,1,0.014,900000,5);
 assert.equal(p.base,2520000);
 assert.equal(p.fee,126000);
 assert.equal(p.total,2646000);
 // rounding: base must always be ceil'd, never floor'd (protects the seller, not the buyer)
 const p2=priceCalc(1,1,0.0141,1,1); // tiny fractional amount
 assert.ok(Number.isInteger(p2.base)&&p2.base>=Math.ceil(1*1*0.0141*1));
});

test('toCsv escapes commas, quotes and newlines correctly',()=>{
 const csv=toCsv([{a:'hello, world',b:'say "hi"',c:'line1\nline2'}]);
 assert.equal(csv,'a,b,c\n"hello, world","say ""hi""","line1\nline2"');
 assert.equal(toCsv([]),''); // empty input -> empty output, no crash
});

test('sniffImage detects real file types from bytes, regardless of claimed mime',()=>{
 assert.equal(sniffImage(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,0,0])),'png');
 assert.equal(sniffImage(Buffer.from([0xff,0xd8,0xff,0xe0,0,0])),'jpeg');
 assert.equal(sniffImage(Buffer.from('GIF89a....')),'gif');
 assert.equal(sniffImage(Buffer.concat([Buffer.from('RIFF'),Buffer.from([0,0,0,0]),Buffer.from('WEBPxxxx')])),'webp');
 assert.equal(sniffImage(Buffer.from('<?php system($_GET[x]); ?>')),null); // malicious upload disguised as image -> rejected
});

test('isValidLottieJson accepts real Lottie shapes and rejects arbitrary JSON',()=>{
 assert.equal(isValidLottieJson(Buffer.from(JSON.stringify({v:'5.9.0',layers:[]}))),true);
 assert.equal(isValidLottieJson(Buffer.from(JSON.stringify({assets:[{id:'a'}]}))),true);
 assert.equal(isValidLottieJson(Buffer.from(JSON.stringify({hello:'world'}))),false); // valid JSON, not Lottie
 assert.equal(isValidLottieJson(Buffer.from('not even json')),false);
 assert.equal(isValidLottieJson(Buffer.from(JSON.stringify(['a','b']))),false); // array, not an object
});

test('RBAC: custom-gift catalog management is restricted to super and inventory',()=>{
 assert.equal(roleHas('super','gifts.manage'),true);
 assert.equal(roleHas('inventory','gifts.manage'),true);
 assert.equal(roleHas('finance','gifts.manage'),false);
 assert.equal(roleHas('support','gifts.manage'),false);
});

test('RBAC: unlisted admins default to super (backward compatible with old ADMIN_IDS-only setups)',()=>{
 const roles=parseAdminRoles('',[111,222]);
 assert.equal(roles[111],'super');
 assert.equal(roles[222],'super');
});

test('RBAC: explicit roles are honored and unknown roles are ignored',()=>{
 const roles=parseAdminRoles('111:finance,222:bogus_role,333:support',[111,222,333,444]);
 assert.equal(roles[111],'finance');
 assert.equal(roles[222],'super');   // bogus role name -> falls back to default
 assert.equal(roles[333],'support');
 assert.equal(roles[444],'super');   // not mentioned at all -> default
});

test('RBAC: permission checks match the intended role boundaries',()=>{
 assert.equal(roleHas('finance','order.refund'),true);
 assert.equal(roleHas('finance','order.fulfill'),false); // finance can refund, not run fulfillment
 assert.equal(roleHas('finance','rate.settings'),true);  // finance can change fee/rate/star price...
 assert.equal(roleHas('finance','settings'),false);      // ...but not toggle maintenance mode / feature flags
 assert.equal(roleHas('support','topup.action'),false);  // support can see the topup queue, not approve money
 assert.equal(roleHas('support','topup.view'),true);
 assert.equal(roleHas('support','order.fulfill'),true);  // support runs day-to-day order fulfillment
 assert.equal(roleHas('viewer','order.fulfill'),false);  // viewer can do nothing but look
 assert.equal(roleHas('viewer','order.view'),true);
 assert.equal(roleHas('inventory','order.refund'),false);
 assert.equal(roleHas('super','settings'),true);
 assert.equal(roleHas('super','rate.settings'),true);
});
