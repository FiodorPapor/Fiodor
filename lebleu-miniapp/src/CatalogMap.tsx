import React,{useEffect,useRef} from 'react';
import {LngLatBounds,Map as MapLibreMap,Marker,NavigationControl,setWorkerUrl} from 'maplibre-gl';
import workerUrl from 'maplibre-gl/dist/maplibre-gl-worker.mjs?worker&url';
import 'maplibre-gl/dist/maplibre-gl.css';

setWorkerUrl(workerUrl);

export type MapListing={
  listingToken:string;code:string;address:string;priceAmount:string;priceCurrency:string;
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

export default function CatalogMap({items,onOpen}:{items:MapListing[];onOpen:(item:MapListing)=>void}){
  const containerRef=useRef<HTMLDivElement|null>(null);
  const mapRef=useRef<MapLibreMap|null>(null);
  const markersRef=useRef<Marker[]>([]);
  const onOpenRef=useRef(onOpen);
  onOpenRef.current=onOpen;

  useEffect(()=>{
    if(!containerRef.current||mapRef.current)return;
    const dark=window.Telegram?.WebApp?.colorScheme==='dark';
    const map=new MapLibreMap({
      container:containerRef.current,
      style:dark?'https://tiles.openfreemap.org/styles/dark':'https://tiles.openfreemap.org/styles/positron',
      center:[-58.43,-34.60],
      zoom:10.7,
      attributionControl:false,
      maxZoom:18,
    });
    map.addControl(new NavigationControl({showCompass:false}),'top-right');
    mapRef.current=map;
    return ()=>{
      markersRef.current.forEach(x=>x.remove());
      markersRef.current=[];
      map.remove();
      mapRef.current=null;
    };
  },[]);

  useEffect(()=>{
    const map=mapRef.current;
    if(!map)return;
    markersRef.current.forEach(x=>x.remove());
    markersRef.current=[];
    const valid=items.filter(x=>Number.isFinite(Number(x.longitude))&&Number.isFinite(Number(x.latitude)));
    const bounds=new LngLatBounds();
    for(const item of valid){
      const el=document.createElement('button');
      el.type='button';
      el.className='priceMarker';
      el.textContent=compactPrice(item);
      el.setAttribute('aria-label',item.address||item.code);
      el.onclick=e=>{e.stopPropagation();onOpenRef.current(item)};
      const marker=new Marker({element:el,anchor:'center'})
        .setLngLat([Number(item.longitude),Number(item.latitude)])
        .addTo(map);
      markersRef.current.push(marker);
      bounds.extend([Number(item.longitude),Number(item.latitude)]);
    }
    if(valid.length===1){
      map.flyTo({center:[Number(valid[0].longitude),Number(valid[0].latitude)],zoom:14,duration:450});
    }else if(valid.length>1&&!bounds.isEmpty()){
      map.fitBounds(bounds,{padding:{top:70,bottom:110,left:42,right:42},maxZoom:14,duration:450});
    }
  },[items]);

  return <div className="mapShell">
    <div ref={containerRef} className="catalogMap"/>
    {!items.some(x=>Number.isFinite(Number(x.longitude))&&Number.isFinite(Number(x.latitude)))&&
      <div className="mapEmpty">У выбранных объектов пока нет координат</div>}
    <div className="mapHint">Нажмите на цену, чтобы открыть объект</div>
  </div>;
}
