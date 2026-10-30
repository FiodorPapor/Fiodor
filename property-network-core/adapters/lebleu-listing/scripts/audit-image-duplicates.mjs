import fs from "node:fs";
import sharp from "sharp";

const catalog=JSON.parse(fs.readFileSync("/opt/lebleu-listing-bridge/public/data/full/catalog.json","utf8"));
const concurrency=12;
let cursor=0;
const tasks=[];
for(const item of catalog){
  for(let index=0; index<(item.imageUrls||[]).length; index++){
    tasks.push({code:item.code,address:item.address||"",sourceUrl:item.sourceUrl,index,url:item.imageUrls[index]});
  }
}

function hamming(a,b){
  let n=0;
  for(let i=0;i<a.length;i++){
    let v=a[i]^b[i];
    while(v){n+=v&1;v>>=1;}
  }
  return n;
}

async function dhash(url){
  const r=await fetch(url,{headers:{"User-Agent":"Mozilla/5.0","Accept":"image/*"},signal:AbortSignal.timeout(8000)});
  if(!r.ok) throw new Error("HTTP "+r.status);
  const buf=Buffer.from(await r.arrayBuffer());
  const {data}=await sharp(buf).resize(17,16,{fit:"fill"}).greyscale().raw().toBuffer({resolveWithObject:true});
  const bits=Buffer.alloc(32);
  let bit=0;
  for(let y=0;y<16;y++){
    for(let x=0;x<16;x++){
      if(data[y*17+x]>data[y*17+x+1]) bits[Math.floor(bit/8)]|=1<<(bit%8);
      bit++;
    }
  }
  return bits;
}

const results=[];
async function worker(){
  while(true){
    const i=cursor++;
    if(i>=tasks.length) return;
    const t=tasks[i];
    try{
      const hash=await dhash(t.url);
      results.push({...t,hash:hash.toString("hex")});
    }catch(e){
      results.push({...t,error:String(e)});
    }
    if((i+1)%250===0) console.error("hashed",i+1,"/",tasks.length);
  }
}
await Promise.all(Array.from({length:concurrency},()=>worker()));

const byListing=new Map();
for(const r of results){
  if(r.error) continue;
  const key=r.sourceUrl||r.url;
  if(!byListing.has(key)) byListing.set(key,[]);
  byListing.get(key).push(r);
}
const within=[];
for(const [sourceUrl,arr] of byListing){
  const code=arr[0]?.code;
  for(let i=0;i<arr.length;i++) for(let j=i+1;j<arr.length;j++){
    const d=hamming(Buffer.from(arr[i].hash,"hex"),Buffer.from(arr[j].hash,"hex"));
    if(d<=10) within.push({code,address:arr[i].address,a:arr[i].index,b:arr[j].index,distance:d,urlA:arr[i].url,urlB:arr[j].url});
  }
}
const exactGroups=new Map();
for(const r of results){
  if(r.error) continue;
  if(!exactGroups.has(r.hash)) exactGroups.set(r.hash,[]);
  exactGroups.get(r.hash).push(r);
}
const cross=[];
for(const [hash,arr] of exactGroups){
  const codes=[...new Set(arr.map(x=>x.code))];
  if(codes.length>1) cross.push({hash,codes,items:arr.map(x=>({code:x.code,index:x.index,url:x.url}))});
}
const report={
  taskCount:tasks.length,
  ok:results.filter(x=>!x.error).length,
  failed:results.filter(x=>x.error).length,
  withinNearDuplicates:within,
  crossExactHashGroups:cross,
  imageHashes:results,
};
fs.writeFileSync("/tmp/lebleu-image-audit.json",JSON.stringify(report,null,2));
console.log(JSON.stringify({
  images:report.taskCount,
  ok:report.ok,
  failed:report.failed,
  within_pairs:within.length,
  within_objects:new Set(within.map(x=>x.code)).size,
  cross_groups:cross.length,
},null,2));
for(const row of within.slice(0,80)){
  console.log("WITHIN",row.code,row.address,"img",row.a+1,"~",row.b+1,"distance",row.distance);
}
