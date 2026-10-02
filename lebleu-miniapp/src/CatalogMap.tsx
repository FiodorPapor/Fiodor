import React,{useEffect,useRef,useState} from 'react';
import OLMap from 'ol/Map.js';
import View from 'ol/View.js';
import Overlay from 'ol/Overlay.js';
import LayerGroup from 'ol/layer/Group.js';
import {defaults as defaultControls} from 'ol/control/defaults.js';
import {defaults as defaultInteractions} from 'ol/interaction/defaults.js';
import {boundingExtent} from 'ol/extent.js';
import {fromLonLat,toLonLat} from 'ol/proj.js';
import {apply} from 'ol-mapbox-style';
import {LocateFixed} from 'lucide-react';
import 'ol/ol.css';

export type MapListing={
  listingToken:string;code:string;address:string;priceAmount:string;priceCurrency:string;
  propertyType?:string;operation?:string;details?:Record<string,number>;images?:string[];
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
  items,onOpen,onFallback,initialViewport,onViewportChange,
}:{
  items:MapListing[];
  onOpen:(item:MapListing)=>void;
  onFallback?:()=>void;
  initialViewport?:{center:[number,number];zoom:number}|null;
  onViewportChange?:(value:{center:[number,number];zoom:number})=>void;
}){
  const containerRef=useRef<HTMLDivElement|null>(null);
  const mapRef=useRef<OLMap|null>(null);
  const markerOverlaysRef=useRef<Overlay[]>([]);
  const userOverlayRef=useRef<Overlay|null>(null);
  const [selectedGroup,setSelectedGroup]=useState<MapListing[]>([]);
  const [ready,setReady]=useState(false);
  const [failure,setFailure]=useState('');
  const [degraded,setDegraded]=useState('');
  const [locating,setLocating]=useState(false);
  const [mapZoom,setMapZoom]=useState(initialViewport?.zoom??10.7);
  const [retryKey,setRetryKey]=useState(0);
  const onOpenRef=useRef(onOpen);
  const onViewportRef=useRef(onViewportChange);
  const restoredViewportRef=useRef(Boolean(initialViewport));
  const lastItemsKeyRef=useRef('');
  onOpenRef.current=onOpen;
  onViewportRef.current=onViewportChange;

  useEffect(()=>{
    const node=containerRef.current;
    if(!node)return;
    setReady(false);
    setFailure('');
    setDegraded('');

    let cancelled=false;
    const baseGroup=new LayerGroup({layers:[]});
    let map:OLMap;

    try{
      map=new OLMap({
        target:node,
        layers:[baseGroup],
        view:new View({
          center:fromLonLat(initialViewport?.center||[-58.43,-34.60]),
          zoom:initialViewport?.zoom??10.7,
          minZoom:3,
          maxZoom:18,
        }),
        controls:defaultControls({
          rotate:false,
          zoom:true,
          attribution:true,
        }),
        interactions:defaultInteractions({
          altShiftDragRotate:false,
          pinchRotate:false,
        }),
        pixelRatio:Math.min(window.devicePixelRatio||1,2),
      });
      mapRef.current=map;
    }catch(error:any){
      setFailure(String(error?.message||'Не удалось запустить карту'));
      return;
    }

    const reveal=()=>{
      if(cancelled)return;
      setReady(true);
      requestAnimationFrame(()=>map.updateSize());
      window.setTimeout(()=>map.updateSize(),180);
      window.setTimeout(()=>map.updateSize(),650);
    };

    // The object layer must never wait for the basemap. Show the Canvas map
    // immediately, then hydrate the background style in parallel.
    reveal();
    const slowStyle=window.setTimeout(()=>{
      if(!cancelled)setDegraded('Фон карты загружается. Объекты уже доступны.');
    },1500);

    apply(baseGroup,'/map/styles/positron')
      .then(()=>{
        window.clearTimeout(slowStyle);
        if(cancelled)return;
        setDegraded('');
        requestAnimationFrame(()=>map.updateSize());
      })
      .catch((error:any)=>{
        window.clearTimeout(slowStyle);
        if(cancelled)return;
        console.warn('OpenLayers basemap error',error);
        setDegraded('Фон карты временно недоступен. Объекты остаются доступными.');
      });

    const resize=()=>map.updateSize();
    const moved=()=>{const c=map.getView().getCenter(),z=map.getView().getZoom();if(c&&z!=null){const p=toLonLat(c);if(onViewportRef.current)onViewportRef.current({center:[p[0],p[1]],zoom:z});setMapZoom(Math.round(z*2)/2);}};
    window.addEventListener('resize',resize,{passive:true});
    map.on('moveend',moved);

    return ()=>{
      cancelled=true;
      window.clearTimeout(slowStyle);
      window.removeEventListener('resize',resize);
      map.un('moveend',moved);
      moved();
      markerOverlaysRef.current.forEach(x=>map.removeOverlay(x));
      markerOverlaysRef.current=[];
      if(userOverlayRef.current){
        map.removeOverlay(userOverlayRef.current);
        userOverlayRef.current=null;
      }
      map.setTarget(undefined);
      map.dispose();
      mapRef.current=null;
    };
  },[retryKey]);

  useEffect(()=>{
    const map=mapRef.current;
    if(!map)return;

    markerOverlaysRef.current.forEach(x=>map.removeOverlay(x));
    markerOverlaysRef.current=[];

    const valid=items.filter(x=>
      Number.isFinite(Number(x.longitude))&&Number.isFinite(Number(x.latitude))
    );
    const itemsKey=items.map(x=>x.listingToken).join('|');
    const itemsChanged=lastItemsKeyRef.current!==itemsKey;
    lastItemsKeyRef.current=itemsKey;
    const precision=mapZoom>=15.5?5:mapZoom>=13.5?4:mapZoom>=11.5?3:2;
    const groups=new Map<string,MapListing[]>();
    for(const item of valid){
      const key=Number(item.longitude).toFixed(precision)+','+Number(item.latitude).toFixed(precision);
      const group=groups.get(key)||[];
      group.push(item);
      groups.set(key,group);
    }

    setSelectedGroup([]);
    for(const group of groups.values()){
      const item=group[0];
      const el=document.createElement('button');
      el.type='button';
      el.className=group.length>1?'priceMarker clusterMarker':'priceMarker';
      el.textContent=group.length>1?String(group.length):compactPrice(item);
      el.setAttribute('aria-label',group.length>1
        ?(group.length+' объектов · '+(item.address||item.code))
        :(item.address||item.code));
      el.onclick=e=>{
        e.preventDefault();
        e.stopPropagation();
        if(group.length===1){onOpenRef.current(item);return;}
        const unique=new Set(group.map(x=>Number(x.longitude).toFixed(5)+','+Number(x.latitude).toFixed(5)));
        const zoom=map.getView().getZoom()||mapZoom;
        if(unique.size>1&&zoom<15.5){
          const coords=group.map(x=>fromLonLat([Number(x.longitude),Number(x.latitude)]));
          map.getView().fit(boundingExtent(coords),{padding:[110,60,150,60],maxZoom:Math.min(16,zoom+2.5),duration:260});
        }else setSelectedGroup(group);
      };
      const markerLon=group.reduce((sum,x)=>sum+Number(x.longitude),0)/group.length;
      const markerLat=group.reduce((sum,x)=>sum+Number(x.latitude),0)/group.length;
      const overlay=new Overlay({
        element:el,
        positioning:'center-center',
        stopEvent:true,
        position:fromLonLat([markerLon,markerLat]),
      });
      map.addOverlay(overlay);
      markerOverlaysRef.current.push(overlay);
    }

    const focus=focusItems(valid);
    if(restoredViewportRef.current){
      restoredViewportRef.current=false;
    }else if(itemsChanged&&valid.length>36){
      const center=[median(valid.map(x=>Number(x.longitude))),median(valid.map(x=>Number(x.latitude)))];
      map.getView().animate({center:fromLonLat(center),zoom:10.8,duration:260});
    }else if(itemsChanged&&focus.length===1){
      map.getView().animate({
        center:fromLonLat([Number(focus[0].longitude),Number(focus[0].latitude)]),
        zoom:14,
        duration:280,
      });
    }else if(itemsChanged&&focus.length>1){
      const coordinates=focus.map(item=>
        fromLonLat([Number(item.longitude),Number(item.latitude)])
      );
      map.getView().fit(boundingExtent(coordinates),{
        padding:[112,44,158,44],
        maxZoom:14,
        duration:320,
      });
    }
    requestAnimationFrame(()=>map.updateSize());

    return ()=>{
      markerOverlaysRef.current.forEach(x=>map.removeOverlay(x));
      markerOverlaysRef.current=[];
    };
  },[items,retryKey,mapZoom]);

  async function locate(){
    const map=mapRef.current;
    if(!map||locating)return;
    setLocating(true);
    setDegraded('');
    try{
      const manager=window.Telegram?.WebApp?.LocationManager;
      let location:any=null;
      if(manager?.init&&manager?.getLocation){
        location=await new Promise<any>((resolve,reject)=>{
          let retries=0;
          const request=()=>{
            if(manager.isLocationAvailable===false){reject(new Error('Геолокация недоступна'));return;}
            manager.getLocation((data:any)=>{
              if(data){resolve(data);return;}
              if(retries<1){retries++;window.setTimeout(request,550);return;}
              reject(new Error('Не удалось определить геопозицию'));
            });
          };
          try{
            if(manager.isInited)request();
            else manager.init(request);
          }catch(error){reject(error);}
        });
      }
      if(!location){
        location=await new Promise<any>((resolve,reject)=>{
          if(!navigator.geolocation){reject(new Error('Геолокация недоступна'));return;}
          navigator.geolocation.getCurrentPosition(
            p=>resolve({latitude:p.coords.latitude,longitude:p.coords.longitude}),
            ()=>reject(new Error('Не удалось определить геопозицию')),
            {enableHighAccuracy:false,timeout:9000,maximumAge:120000},
          );
        });
      }
      const coordinate=fromLonLat([Number(location.longitude),Number(location.latitude)]);
      if(userOverlayRef.current)map.removeOverlay(userOverlayRef.current);
      const el=document.createElement('div');
      el.className='userLocationDot';
      const overlay=new Overlay({element:el,positioning:'center-center',stopEvent:false,position:coordinate});
      map.addOverlay(overlay);
      userOverlayRef.current=overlay;
      map.getView().animate({center:coordinate,zoom:14.4,duration:320});
    }catch{
      setDegraded('Не удалось определить геопозицию');
      window.setTimeout(()=>setDegraded(''),3200);
    }finally{
      setLocating(false);
    }
  }

  const hasGeo=items.some(x=>
    Number.isFinite(Number(x.longitude))&&Number.isFinite(Number(x.latitude))
  );

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

    {ready&&!!degraded&&<div className="mapDegraded">{degraded}</div>}

    {ready&&<button className="mapLocateBtn" onClick={locate} disabled={locating} aria-label="Моё местоположение">
      <LocateFixed size={18}/><span>{locating?'Ищем…':'Моё место'}</span>
    </button>}

    {!hasGeo&&<div className="mapEmpty">У выбранных объектов пока нет координат</div>}

    {!!selectedGroup.length&&<div className="mapGroupPanel">
      <div className="mapGroupHead">
        <strong>{selectedGroup.length} объектов рядом</strong>
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
