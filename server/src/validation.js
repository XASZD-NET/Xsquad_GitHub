export const validUsername=s=>/^[a-zA-Z0-9-]{3,39}$/.test(s||'');
export const validRepoName=s=>/^[a-zA-Z0-9._-]{1,100}$/.test(s||'')&&s!=='.'&&s!=='..';
export const validRepoPath=s=>typeof s==='string'&&s.length>0&&s.length<=500&&!s.startsWith('/')&&s.split('/').every(x=>x&&x!=='.'&&x!=='..'&&!x.includes('\\\\'));
