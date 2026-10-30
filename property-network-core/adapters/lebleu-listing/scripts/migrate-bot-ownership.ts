import fs from "node:fs/promises";
import crypto from "node:crypto";

const ROOT="/opt/lebleu-listing-bridge";
const STATE_FILE=ROOT+"/state/telegram-state.json";
const CATALOG=ROOT+"/public/data/full/catalog.json";
const PUB_ENV=ROOT+"/publisher.env";
const CRM_ENV="/opt/fiodor-crm-v2/.env";

function env(text:string){const o:Record<string,string>={}; for(const raw of text.split(/\r?\n/)){const s=raw.trim(); if(!s||s.startsWith("#")||!s.includes("="))continue; const i=s.indexOf("=");o[s.slice(0,i)]=s.slice(i+1)} return o}
function codeOf(item:any){return String(item.code||item.slug||crypto.createHash("sha256").update(item.sourceUrl).digest("hex").slice(0,12)).trim()}
function startPayload(item:any){const u=crypto.createHash("sha256").update(item.sourceUrl).digest("hex").slice(0,8);return ("lb_"+codeOf(item)+"_"+u).replace(/[^A-Za-z0-9_-]/g,"_").slice(0,64)}
async function api(token:string,method:string,payload:any){
 for(let a=0;a<3;a++){
  const r=await fetch("https://api.telegram.org/bot"+token+"/"+method,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(payload),signal:AbortSignal.timeout(15000)});
  const b:any=await r.json().catch(()=>({}));
  if(b.ok)return b.result;
  const retry=Number(b?.parameters?.retry_after||0);
  if((r.status===429||retry)&&a<2){await new Promise(x=>setTimeout(x,(Math.max(1,retry)*1000)+500));continue}
  throw new Error(method+": "+(b?.description||r.status));
 }
}

async function main(){
 const apply=process.argv.includes("--apply");
 const onlyIdx=process.argv.indexOf("--only-code");
 const only=onlyIdx>=0?String(process.argv[onlyIdx+1]||""):"";
 const cfg=env(await fs.readFile(PUB_ENV,"utf8")); const crm=env(await fs.readFile(CRM_ENV,"utf8"));
 const oldToken=crm.TELEGRAM_BOT_TOKEN, newToken=crm.LEBLEU_TELEGRAM_BOT_TOKEN;
 const bot=cfg.TELEGRAM_BOT_USERNAME||crm.LEBLEU_TELEGRAM_BOT_USERNAME||"LeBleuArgentinaBot";
 const channel=cfg.TELEGRAM_CHANNEL;
 if(!oldToken||!newToken||!channel)throw new Error("tokens/channel missing");
 const state:any=JSON.parse(await fs.readFile(STATE_FILE,"utf8"));
 const catalog:any[]=JSON.parse(await fs.readFile(CATALOG,"utf8"));
 const byUrl=new Map(catalog.map(x=>[x.sourceUrl,x]));
 let migrated=0,skipped=0,errors=0;
 for(const [url,entry] of Object.entries<any>(state.entries)){
  if(only&&entry.code!==only)continue;
  const owner=String(entry.botUsername||"FiodorCRMControlBot").replace(/^@/,"").toLowerCase();
  if(owner===bot.replace(/^@/,"").toLowerCase()){skipped++;continue}
  const item=byUrl.get(url); if(!item){console.warn("SKIP missing catalog",entry.code);skipped++;continue}
  console.log((apply?"MIGRATE ":"WOULD_MIGRATE ")+entry.code);
  if(!apply){migrated++;continue}
  try{
   const oldIds=[...(entry.messageIds||[]),...(entry.ctaMessageId?[entry.ctaMessageId]:[])];
   const copied:any[]=await api(newToken,"copyMessages",{chat_id:channel,from_chat_id:channel,message_ids:oldIds,message_thread_id:entry.threadId,disable_notification:true});
   const newIds=copied.map(x=>Number(x.message_id));
   if(newIds.length!==oldIds.length)throw new Error("copy count "+newIds.length+"/"+oldIds.length);
   const mediaCount=(entry.messageIds||[]).length;
   const messageIds=newIds.slice(0,mediaCount);
   const ctaMessageId=entry.ctaMessageId?newIds[mediaCount]:undefined;
   const lead="https://t.me/"+bot.replace(/^@/,"")+"?start="+startPayload(item);
   const reply_markup={inline_keyboard:[[{text:"Узнать подробнее",url:lead}]]};
   const target=entry.mode==="album"&&ctaMessageId?ctaMessageId:messageIds[0];
   await api(newToken,"editMessageReplyMarkup",{chat_id:channel,message_id:target,reply_markup});
   state.entries[url]={...entry,messageIds,ctaMessageId,botUsername:bot,updatedAt:new Date().toISOString()};
   const tmp=STATE_FILE+".tmp"; await fs.writeFile(tmp,JSON.stringify(state,null,2)); await fs.rename(tmp,STATE_FILE);
   for(const id of oldIds){try{await api(oldToken,"deleteMessage",{chat_id:channel,message_id:id})}catch(e){console.warn("old delete skipped",entry.code,id,String(e))}}
   migrated++; await new Promise(x=>setTimeout(x,500));
  }catch(e){errors++;console.error("ERROR",entry.code,String(e)); if(only)throw e}
 }
 console.log(JSON.stringify({apply,only:only||null,migrated,skipped,errors}));
}
main().catch(e=>{console.error(e);process.exit(1)});
