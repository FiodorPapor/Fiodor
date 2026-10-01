import React,{useEffect,useRef,useState} from 'react';
import {
  GeolocateControl,LngLatBounds,Map as MapLibreMap,Marker,NavigationControl,setWorkerUrl
} from 'maplibre-gl';
import workerUrl from 'maplibre-gl/dist/maplibre-gl-worker.mjs?worker&url';
import 'maplibre-gl/dist/maplibre-gl.css';

setWorkerUrl(workerUrl);

export type MapListing={
  listingToken:string;code:string;address:string;priceAmount:string;priceCurrency:string;
  propertyType?:string;operation?:string;details?:Record<string,number>;
  latitude?:number|null;longitude?:number|null;
};

function compactPrice(item:MapListing){
  const n=Number(item.priceAmount||0);
  if(!Number.isFinite(n)||!n)return item.priceCurrency||'';
  const prefix=item.priceCurrency==='USD'?'US$':item.priceCurrency==='ARS'?'$':'';
  if(n>=1_000_000)return prefix+(n/1_000_000).toFixed(n>=10_000_000?0:1).replace('.0','')+'M';
  if(n>=1000)return prefix+Math.round(n/1000)+'k';
  return prefix+Math.round(n);
}
function median(values:number[]){
  if(!values.length)return 0;
  const sorted=[...values].sort((a,b)=>a-b);
  const mid=Math.floor(sorted.length/2);
  return sorted.length%2?sorted[mid]:(sorted[mid-1]+sorted[mid])/2;
}
function focusItems(items:MapListing[]){
  if(items.length<=40)return items;
  const centerLat=median(items.map(x=>Number(x.latitude)));
  const centerLng=median(items.map(x=>Number(x.longitude)));
  const ranked=items.map(item=>{
    const lat=Number(item.latitude),lng=Number(item.longitude);
    const dx=(lng-centerLng)*Math.cos(centerLat*Math.PI/180);
    const dy=lat-centerLat;
    return {item,distance:dx*dx+dy*dy};
  }).sort((a,b)=>a.distance-b.distance);
  return ranked.slice(0,Math.max(2,Math.ceil(ranked.length*.92))).map(x=>x.item);
}

export default function CatalogMap({
  items,onOpen,onFallback,
}:{
  items:MapListing[];
  onOpen:(item:MapListing)=>void;
  onFallback?:()=>void;
}){
  const containerRef=useRef<HTMLDivElement|null>(null);
  const mapRef=useRef<MapLibreMap|null>(null);
  const markersRef=useRef<Marker[]>([]);
  const [selectedGroup,setSelectedGroup]=useState<MapListing[]>([]);
  const [ready,setReady]=useState(false);
  const [failure,setFailure]=useState('');
  const [retryKey,setRetryKey]=useState(0);
  const onOpenRef=useRef(onOpen);
  onOpenRef.current=onOpen;

  useEffect(()=>{
    const node=containerRef.current;
    if(!node)return;
    setReady(false);
    setFailure('');
    let timedOut=false;
    let map:MapLibreMap|null=null;

    try{
      map=new MapLibreMap({
        container:node,
        style:'/map/styles/positron',
        center:[-58.43,-34.60],
        zoom:10.7,
        maxZoom:18,
        attributionControl:{compact:true},
        cooperativeGestures:false,
        renderWorldCopies:false,
      });
      mapRef.current=map;
    }catch(error:any){
      const message=String(error?.message||error||'');
      setFailure(/webgl|gpu/i.test(message)
        ?'Карта не смогла запуститься в этом WebView. Откройте список или повторите попытку.'
        :'Не удалось запустить карту. Откройте список или повторите попытку.');
      return;
    }

    const timeout=window.setTimeout(()=>{
      if(!map?.loaded()){
        timedOut=true;
        setFailure('Картографический слой не ответил вовремя. Можно повторить или вернуться к списку.');
      }
    },12000);

    map.once('load',()=>{
      window.clearTimeout(timeout);
      if(!timedOut){
        setReady(true);
        setFailure('');
      }
      requestAnimationFrame(()=>map?.resize());
      window.setTimeout(()=>map?.resize(),180);
      window.setTimeout(()=>map?.resize(),700);
    });

    map.on('error',(event:any)=>{
      const message=String(event?.error?.message||event?.error||'');
      if(/webgl|gpu|context lost/i.test(message)){
        timedOut=true;
        window.clearTimeout(timeout);
        setFailure('Графический режим карты недоступен. Вернитесь к списку или повторите попытку.');
      }else{
        console.warn('Map resource error',event?.error||event);
      }
    });

    map.addControl(new NavigationControl({showCompass:false}),'top-right');
    map.addControl(new GeolocateControl({
      positionOptions:{enableHighAccuracy:false,timeout:6000},
      trackUserLocation:false,
      showAccuracyCircle:false,
      showUserLocation:true,
    }),'top-right');

    return ()=>{
      window.clearTimeout(timeout);
      markersRef.current.forEach(x=>x.remove());
      markersRef.current=[];
      try{map?.remove();}catch{}
      mapRef.current=null;
    };
  },[retryKey]);

  useEffect(()=>{
    const map=mapRef.current;
    if(!map)return;

    const renderMarkers=()=>{
      markersRef.current.forEach(x=>x.remove());
      markersRef.current=[];
      const valid=items.filter(x=>Number.isFinite(Number(x.longitude))&&Number.isFinite(Number(x.latitude)));
      const groups=new Map<string,MapListing[]>();
      for(const item of valid){
        const key=Number(item.longitude).toFixed(5)+','+Number(item.latitude).toFixed(5);
        const group=groups.get(key)||[];
        group.push(item);
        groups.set(key,group);
      }

      setSelectedGroup([]);
      for(const group of groups.values()){
        const item=group[0];
        const el=document.createElement('button');
        el.type='button';
        el.className=group.length>1?'priceMarker groupMarker':'priceMarker';
        el.textContent=group.length>1?(group.length+' вариантов'):compactPrice(item);
        el.setAttribute('aria-label',group.length>1
          ?(group.length+' объектов · '+(item.address||item.code))
          :(item.address||item.code));
        el.onclick=e=>{
          e.stopPropagation();
          if(group.length===1)onOpenRef.current(item);
          else setSelectedGroup(group);
        };
        const marker=new Marker({element:el,anchor:'center'})
          .setLngLat([Number(item.longitude),Number(item.latitude)])
          .addTo(map);
        markersRef.current.push(marker);
      }

      const focus=focusItems(valid);
      const bounds=new LngLatBounds();
      for(const item of focus){
        bounds.extend([Number(item.longitude),Number(item.latitude)]);
      }
      if(focus.length===1){
        map.flyTo({center:[Number(focus[0].longitude),Number(focus[0].latitude)],zoom:14,duration:300});
      }else if(focus.length>1&&!bounds.isEmpty()){
        map.fitBounds(bounds,{padding:{top:112,bottom:158,left:44,right:44},maxZoom:14,duration:360});
      }
    };

    if(map.loaded())renderMarkers();
    else map.once('load',renderMarkers);
    return ()=>{try{map.off('load',renderMarkers);}catch{}};
  },[items,retryKey]);

  const hasGeo=items.some(x=>Number.isFinite(Number(x.longitude))&&Number.isFinite(Number(x.latitude)));

  return <div className="mapShell">
    <div ref={containerRef} className="catalogMap"/>
    {!ready&&!failure&&<div className="mapBoot"><div className="spinner"/><span>Загружаем карту…</span></div>}
    {!!failure&&<div className="mapFailure">
      <strong>Карта пока недоступна</strong>
      <span>{failure}</span>
      <div>
        <button className="primary" onClick={()=>setRetryKey(x=>x+1)}>Повторить</button>
        {onFallback&&<button className="mapFallbackBtn" onClick={onFallback}>Показать списком</button>}
      </div>
    </div>}
    {!hasGeo&&<div className="mapEmpty">У выбранных объектов пока нет координат</div>}
    {!!selectedGroup.length&&<div className="mapGroupPanel">
      <div className="mapGroupHead">
        <strong>{selectedGroup.length} вариантов по этому адресу</strong>
        <button onClick={()=>setSelectedGroup([])}>×</button>
      </div>
      <div className="mapGroupList">
        {selectedGroup.slice().sort((a,b)=>Number(a.priceAmount||0)-Number(b.priceAmount||0)).map(item=>
          <button key={item.listingToken} onClick={()=>onOpenRef.current(item)}>
            <span>{compactPrice(item)}</span>
            <small>{item.address||item.code}</small>
          </button>)}
      </div>
    </div>}
  </div>;
}
