import React,{useEffect,useRef,useState} from 'react';
import OLMap from 'ol/Map.js';
import View from 'ol/View.js';
import Overlay from 'ol/Overlay.js';
import LayerGroup from 'ol/layer/Group.js';
import {defaults as defaultControls} from 'ol/control/defaults.js';
import {defaults as defaultInteractions} from 'ol/interaction/defaults.js';
import {fromLonLat} from 'ol/proj.js';
import {apply} from 'ol-mapbox-style';
import {ExternalLink,LocateFixed,MapPin,Maximize2,Minimize2} from 'lucide-react';
import {tx} from './i18n';
import 'ol/ol.css';

export default function DetailMap({latitude,longitude,address,onOpenExternal}:{
  latitude:number;longitude:number;address:string;onOpenExternal:()=>void;
}){
  const nodeRef=useRef<HTMLDivElement|null>(null);
  const mapRef=useRef<OLMap|null>(null);
  const userOverlayRef=useRef<Overlay|null>(null);
  const [ready,setReady]=useState(false);
  const [degraded,setDegraded]=useState(false);
  const [expanded,setExpanded]=useState(false);
  const [locating,setLocating]=useState(false);
  const [locationNote,setLocationNote]=useState('');

  useEffect(()=>{
    const node=nodeRef.current;
    if(!node)return;
    const center=fromLonLat([longitude,latitude]);
    const baseGroup=new LayerGroup({layers:[]});
    const map=new OLMap({
      target:node,
      layers:[baseGroup],
      view:new View({center,zoom:16.2,minZoom:3,maxZoom:20}),
      controls:defaultControls({rotate:false,zoom:true,attribution:true}),
      interactions:defaultInteractions({
        altShiftDragRotate:false,
        pinchRotate:false,
        mouseWheelZoom:false,
      }),
      pixelRatio:Math.min(window.devicePixelRatio||1,2),
    });
    mapRef.current=map;
    const pin=document.createElement('div');
    pin.className='detailMapPin';
    const overlay=new Overlay({element:pin,position:center,positioning:'bottom-center',stopEvent:false});
    map.addOverlay(overlay);
    let cancelled=false;
    // Bright keeps the map readable but adds building footprints, land use and
    // POIs that are useful when evaluating a property's immediate surroundings.
    apply(baseGroup,'/map/styles/bright').then(()=>{
      if(!cancelled){setReady(true);requestAnimationFrame(()=>map.updateSize());}
    }).catch(()=>{if(!cancelled){setReady(true);setDegraded(true);}});
    const timer=window.setTimeout(()=>{if(!cancelled)setReady(true);},1000);
    return ()=>{
      cancelled=true;
      window.clearTimeout(timer);
      if(userOverlayRef.current){map.removeOverlay(userOverlayRef.current);userOverlayRef.current=null;}
      map.removeOverlay(overlay);
      map.setTarget(undefined);
      map.dispose();
      mapRef.current=null;
    };
  },[latitude,longitude]);

  useEffect(()=>{
    const map=mapRef.current;
    if(!map)return;
    requestAnimationFrame(()=>map.updateSize());
    window.setTimeout(()=>map.updateSize(),180);
    if(!expanded)return;
    const oldBody=document.body.style.overflow;
    const oldHtml=document.documentElement.style.overflow;
    document.body.style.overflow='hidden';
    document.documentElement.style.overflow='hidden';
    return ()=>{
      document.body.style.overflow=oldBody;
      document.documentElement.style.overflow=oldHtml;
    };
  },[expanded]);

  function recenter(){
    const map=mapRef.current;
    if(!map)return;
    map.getView().animate({center:fromLonLat([longitude,latitude]),zoom:16.2,duration:260});
  }

  async function locate(){
    const map=mapRef.current;
    if(!map||locating)return;
    setLocating(true);
    setLocationNote('');
    try{
      const manager=window.Telegram?.WebApp?.LocationManager;
      let location:any=null;
      if(manager?.init&&manager?.getLocation){
        location=await new Promise<any>((resolve,reject)=>{
          let retries=0;
          const request=()=>{
            if(manager.isLocationAvailable===false){reject(new Error(tx('map.geoUnavailable')));return;}
            manager.getLocation((data:any)=>{
              if(data){resolve(data);return;}
              if(retries<1){retries++;window.setTimeout(request,500);return;}
              reject(new Error(tx('map.geoFailed')));
            });
          };
          try{if(manager.isInited)request();else manager.init(request);}catch(error){reject(error);}
        });
      }
      if(!location){
        location=await new Promise<any>((resolve,reject)=>{
          if(!navigator.geolocation){reject(new Error(tx('map.geoUnavailable')));return;}
          navigator.geolocation.getCurrentPosition(
            p=>resolve({latitude:p.coords.latitude,longitude:p.coords.longitude,accuracy:p.coords.accuracy}),
            ()=>reject(new Error(tx('map.geoPermission'))),
            {enableHighAccuracy:true,timeout:9000,maximumAge:60000},
          );
        });
      }
      const coordinate=fromLonLat([Number(location.longitude),Number(location.latitude)]);
      if(userOverlayRef.current)map.removeOverlay(userOverlayRef.current);
      const dot=document.createElement('div');
      dot.className='userLocationDot detailUserLocationDot';
      const userOverlay=new Overlay({element:dot,positioning:'center-center',stopEvent:false,position:coordinate});
      map.addOverlay(userOverlay);
      userOverlayRef.current=userOverlay;
      map.getView().animate({center:coordinate,zoom:Math.max(16,map.getView().getZoom()||16),duration:320});
      setLocationNote(tx('map.yourLocation'));
      window.setTimeout(()=>setLocationNote(''),1800);
    }catch(error:any){
      setLocationNote(error?.message||tx('map.geoFailed'));
      window.setTimeout(()=>setLocationNote(''),3000);
    }finally{
      setLocating(false);
    }
  }

  return <div className={expanded?'detailMapCard detailMapExpanded':'detailMapCard'}>
    <div className="detailMapCanvas" ref={nodeRef}/>
    {!ready&&<div className="detailMapLoading">{tx('map.loading')}</div>}
    {degraded&&<div className="detailMapDegraded">{tx('map.backgroundUnavailable')}</div>}
    {!!locationNote&&<div className="detailMapLocationNote">{locationNote}</div>}
    <div className="detailMapTools">
      <button type="button" onClick={locate} disabled={locating} aria-label={tx('map.myLocation')} title={tx('map.myLocation')}><LocateFixed size={17}/></button>
      <button type="button" onClick={recenter} aria-label={tx('map.backToObject')} title={tx('map.backToObject')}><MapPin size={17}/></button>
      <button type="button" onClick={()=>setExpanded(v=>!v)} aria-label={expanded?tx('map.collapse'):tx('map.expand')} title={expanded?tx('map.collapse'):tx('map.expand')}>
        {expanded?<Minimize2 size={17}/>:<Maximize2 size={17}/>}
      </button>
    </div>
    <div className="detailMapFooter">
      <span><MapPin size={16}/><b>{address||tx('map.objectLocation')}</b></span>
      <button type="button" className="detailMapOpen" onClick={onOpenExternal} aria-label={tx('map.openGoogle',{name:address||tx('propertyType.property')})}>
        <span>Google Maps</span><ExternalLink size={14}/>
      </button>
    </div>
  </div>;
}
