// Offline V8 layout benchmark; no browser DOM, provider calls or external data.
const fs = require('fs');
const source = fs.readFileSync(process.argv[2], 'utf8');
const start = source.includes('function spatialPairs(') ? source.indexOf('function spatialPairs(') : source.indexOf('function networkLayout(');
const script = source.slice(start, source.indexOf('function updateClusterGuides()', start));
const count = Number(process.argv[3] || 1200);
const nodes = Array.from({length: count}, (_, i) => ({id: 'n'+i, label: 'Node '+i, kind: 'kind'+i%8, degree: 2}));
const edges = nodes.slice(1).map((node,i) => ({source: 'n'+i, target: node.id}));
const run = new Function('nodes','edges', `
const width=1800,height=1000,layoutNodes=nodes,layoutEdges=edges,byId=new Map(nodes.map(n=>[n.id,n]));
const present=[...new Set(nodes.map(n=>n.kind))],groups=new Map(present.map(k=>[k,nodes.filter(n=>n.kind===k)])),expandedUrls=new Map();
function hashNumber(value){let hash=2166136261;for(const char of String(value)){hash^=char.charCodeAt(0);hash=Math.imul(hash,16777619)}return(hash>>>0)/4294967295}
const started=performance.now();
${script}
const positions=layoutPositions('${process.argv.includes('--groups') ? 'groups' : 'network'}');
const milliseconds=performance.now()-started;
let minimum=Infinity;
const points=[...positions.values()];
for(let i=0;i<points.length;i++)for(let j=i+1;j<points.length;j++)minimum=Math.min(minimum,Math.hypot(points[i].x-points[j].x,points[i].y-points[j].y));
return {nodes:nodes.length,milliseconds,minimum};`);
if (process.argv.includes('--html')) {
  console.log('<!doctype html><meta charset="utf-8"><title>Offline Cachaza benchmark</title><pre id="results"></pre><script>' +
    'document.getElementById("results").textContent=JSON.stringify((' + run.toString() + ')(' +
    JSON.stringify(nodes) + ',' + JSON.stringify(edges) + '),null,2);</script>');
} else console.log(JSON.stringify(run(nodes,edges)));
