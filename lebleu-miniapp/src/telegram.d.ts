export {};
declare global {
  interface Window { Telegram?: { WebApp?: any } }
}
declare module '*?worker&url' {
  const src: string;
  export default src;
}
