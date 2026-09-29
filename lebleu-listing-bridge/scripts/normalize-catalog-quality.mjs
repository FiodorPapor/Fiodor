import fs from "node:fs";
import path from "node:path";
import sharp from "sharp";

const ROOT="/opt/lebleu-listing-bridge";
const CATALOG=path.join(ROOT,"public/data/full/catalog.json");
const CACHE=path.join(ROOT,"state/image-phash-cache.json");
const REPORT=path.join(ROOT,"state/catalog-quality.json");
const VERSION="dedupe-v1";

const items=JSON.parse(fs.readFileSync(CATALOG,"utf8"));
let cache={};
try{cache=JSON.parse(fs.readFileSync(CACHE,"utf8"));}catch{}

function textNorm(s){
  return String(s||"").toLowerCase()
    .normalize("NFD").replace(/[\u0300-\u036f]/g,"")
    .replace(/[^a-z0-9а-я]+/gi," ").replace(/\s+/g," ").trim();
}
function tokens(s){
  return new Set(textNorm(s).split(" ").filter(x=>x.length>=4));
}
function jaccard(a,b){
  const A=tokens(a),B=tokens(b);
  if(!A.size&&!B.size)return 0;
  let inter=0;
  for(const x of A) if(B.has(x)) inter++;
  return inter/(A.size+B.size-inter);
}
function area(i){
  const d=i.details||{};
  return d.totalAreaM2??d.coveredAreaM2??null;
}
function codeNumber(i){
  const m=String(i.code||"").match(/(\d+)/);
  return m?Number(m[1]):0;
}
function samePhysical(a,b){
  if(a.operation!==b.operation) return false;
  if(!textNorm(a.address)||textNorm(a.address)!==textNorm(b.address)) return false;
  const da=a.details||{}, db=b.details||{};
  const aa=area(a), ab=area(b);
  const descA=textNorm(a.description), descB=textNorm(b.description);
  const exactDesc=descA.length>120 && descA===descB;
  const similarity=jaccard(a.description,b.description);
  const roomsCompatible=da.rooms==null||db.rooms==null||da.rooms===db.rooms;
  const bedsCompatible=da.bedrooms==null||db.bedrooms==null||da.bedrooms===db.bedrooms;
  const typeCompatible=a.propertyType===b.propertyType||exactDesc;
  if(!roomsCompatible||!bedsCompatible||!typeCompatible) return false;
  if(aa!=null&&ab!=null){
    const rel=Math.abs(Number(aa)-Number(ab))/Math.max(Number(aa),Number(ab),1);
    if(rel>0.03) return false;
    return exactDesc||similarity>=0.93;
  }
  return exactDesc && String(a.priceAmount||"")===String(b.priceAmount||"");
}

const parent=items.map((_,i)=>i);
function find(x){while(parent[x]!==x){parent[x]=parent[parent[x]];x=parent[x];}return x;}
function union(a,b){a=find(a);b=find(b);if(a!==b)parent[b]=a;}
for(let i=0;i<items.length;i++){
  for(let j=i+1;j<items.length;j++){
    if(samePhysical(items[i],items[j])) union(i,j);
  }
}
const groups=new Map();
for(let i=0;i<items.length;i++){
  const r=find(i);
  if(!groups.has(r)) groups.set(r,[]);
  groups.get(r).push(i);
}
const suppressed=[];
const kept=[];
for(const idxs of groups.values()){
  const ranked=[...idxs].sort((a,b)=>codeNumber(items[b])-codeNumber(items[a]));
  const winner=ranked[0];
  kept.push(items[winner]);
  for(const loser of ranked.slice(1)){
    suppressed.push({
      keptCode:items[winner].code,
      keptUrl:items[winner].sourceUrl,
      suppressedCode:items[loser].code,
      suppressedUrl:items[loser].sourceUrl,
      address:items[loser].address,
      operation:items[loser].operation,
      reason:"same_physical_listing",
    });
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
  if(cache[url]?.hash) return Buffer.from(cache[url].hash,"hex");
  const r=await fetch(url,{headers:{"User-Agent":"Mozilla/5.0","Accept":"image/*"},signal:AbortSignal.timeout(8000)});
  if(!r.ok) throw new Error("HTTP "+r.status);
  const buf=Buffer.from(await r.arrayBuffer());
  const {data}=await sharp(buf).resize(17,16,{fit:"fill"}).greyscale().raw().toBuffer({resolveWithObject:true});
  const bits=Buffer.alloc(32);
  let bit=0;
  for(let y=0;y<16;y++) for(let x=0;x<16;x++){
    if(data[y*17+x]>data[y*17+x+1]) bits[Math.floor(bit/8)]|=1<<(bit%8);
    bit++;
  }
  cache[url]={hash:bits.toString("hex")};
  return bits;
}

const photoDrops=[];
let imageErrors=0;
let processed=0;
for(const item of kept){
  const unique=[];
  const hashes=[];
  for(const url of item.imageUrls||[]){
    try{
      const h=await dhash(url);
      let duplicateOf=-1;
      for(let i=0;i<hashes.length;i++){
        if(hamming(h,hashes[i])<=10){duplicateOf=i;break;}
      }
      if(duplicateOf>=0){
        photoDrops.push({
          code:item.code,sourceUrl:item.sourceUrl,address:item.address,
          droppedUrl:url,keptUrl:unique[duplicateOf],
        });
      }else{
        unique.push(url);hashes.push(h);
      }
    }catch(e){
      imageErrors++;
      unique.push(url);
    }
  }
  item.imageUrls=unique;
  processed++;
  if(processed%25===0) console.error("quality images",processed,"/",kept.length);
}

fs.writeFileSync(CACHE,JSON.stringify(cache));
fs.writeFileSync(CATALOG,JSON.stringify(kept,null,2));
const report={
  version:VERSION,
  inputCount:items.length,
  outputCount:kept.length,
  suppressedCount:suppressed.length,
  suppressed,
  duplicatePhotosRemoved:photoDrops.length,
  affectedPhotoListings:[...new Set(photoDrops.map(x=>x.sourceUrl))].length,
  photoDrops,
  imageErrors,
  generatedAt:new Date().toISOString(),
};
fs.writeFileSync(REPORT,JSON.stringify(report,null,2));
console.log(JSON.stringify({
  input:report.inputCount,
  output:report.outputCount,
  suppressed:report.suppressedCount,
  duplicate_photos_removed:report.duplicatePhotosRemoved,
  photo_listings_affected:report.affectedPhotoListings,
  image_errors:report.imageErrors,
},null,2));
for(const x of suppressed) console.log("SUPPRESS",x.suppressedCode,"->",x.keptCode,x.address);
