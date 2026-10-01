import React,{useEffect,useRef,useState} from 'react';
import {GeolocateControl,LngLatBounds,Map as MapLibreMap,Marker,NavigationControl,setWorkerUrl} from 'maplibre-gl';
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

export default function CatalogMap({items,onOpen}:{items:MapListing[];onOpen:(item:MapListing)=>void}){
  const containerRef=useRef<HTMLDivElement|null>(null);
  const mapRef=useRef<MapLibreMap|null>(null);
  const markersRef=useRef<Marker[]>([]);
  const [selectedGroup,setSelectedGroup]=useState<MapListing[]>([]);
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
      maxZoom:18,
    });
    map.addControl(new NavigationControl({showCompass:false}),'top-right');
    map.addControl(new GeolocateControl({
      positionOptions:{enableHighAccuracy:false,timeout:6000},
      trackUserLocation:false,
      showAccuracyCircle:false,
      showUserLocation:true,
    }),'top-right');
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
    const groups=new Map<string,MapListing[]>();
    for(const item of valid){
      const key=Number(item.longitude).toFixed(5)+','+Number(item.latitude).toFixed(5);
      const group=groups.get(key)||[];
      group.push(item);
      groups.set(key,group);
    }
    const bounds=new LngLatBounds();
    setSelectedGroup([]);
    for(const group of groups.values()){
      const item=group[0];
      const el=document.createElement('button');
      el.type='button';
      el.className=group.length>1?'priceMarker groupMarker':'priceMarker';
      el.textContent=group.length>1?(group.length+' вариантов'):compactPrice(item);
      el.setAttribute('aria-label',group.length>1?(group.length+' объектов · '+(item.address||item.code)):(item.address||item.code));
      el.onclick=e=>{
        e.stopPropagation();
        if(group.length===1) onOpenRef.current(item);
        else setSelectedGroup(group);
      };
      const marker=new Marker({element:el,anchor:'center'})
        .setLngLat([Number(item.longitude),Number(item.latitude)])
        .addTo(map);
      markersRef.current.push(marker);
      bounds.extend([Number(item.longitude),Number(item.latitude)]);
    }
    if(groups.size===1&&valid.length){
      map.flyTo({center:[Number(valid[0].longitude),Number(valid[0].latitude)],zoom:14,duration:450});
    }else if(groups.size>1&&!bounds.isEmpty()){
      map.fitBounds(bounds,{padding:{top:70,bottom:120,left:42,right:42},maxZoom:14,duration:450});
    }
  },[items]);

  return <div className="mapShell">
    <div ref={containerRef} className="catalogMap"/>
    {!items.some(x=>Number.isFinite(Number(x.longitude))&&Number.isFinite(Number(x.latitude)))&&
      <div className="mapEmpty">У выбранных объектов пока нет координат</div>}
    {!!selectedGroup.length&&<div className="mapGroupPanel">
      <div className="mapGroupHead"><strong>{selectedGroup.length} вариантов по этому адресу</strong><button onClick={()=>setSelectedGroup([])}>×</button></div>
      <div className="mapGroupList">
        {selectedGroup.slice().sort((a,b)=>Number(a.priceAmount||0)-Number(b.priceAmount||0)).map(item=>
          <button key={item.listingToken} onClick={()=>onOpenRef.current(item)}>
            <span>{compactPrice(item)}</span><small>{item.address||item.code}</small>
          </button>)}
      </div>
    </div>}
    {!selectedGroup.length&&<div className="mapHint">Нажмите на цену, чтобы открыть объект</div>}
  </div>;
}
