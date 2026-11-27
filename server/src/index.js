import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { Pool } from 'pg';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 10000);
const MAX_FILE_BYTES = Number(process.env.MAX_FILE_BYTES || 2 * 1024 * 1024);
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 10, idleTimeoutMillis: 30000, connectionTimeoutMillis: 10000
});
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(compression());
const origins = (process.env.CLIENT_ORIGIN || '').split(',').map(s=>s.trim()).filter(Boolean);
app.use(cors({ origin: (origin, cb) => {
  if (!origin || process.env.NODE_ENV !== 'production' || !origins.length || origins.includes(origin)) return cb(null,true);
  return cb(new Error('Origin not allowed'));
}}));
app.use(express.json({ limit: `${Math.ceil(MAX_FILE_BYTES/1024/1024)+1}mb` }));
app.use('/api', rateLimit({windowMs:60000,limit:120,standardHeaders:true,legacyHeaders:false}));
app.use('/api/auth', rateLimit({windowMs:900000,limit:15,standardHeaders:true,legacyHeaders:false}));

const schema = `
CREATE TABLE IF NOT EXISTS users (
 id BIGSERIAL PRIMARY KEY, username VARCHAR(39) UNIQUE NOT NULL, email VARCHAR(254) UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, display_name VARCHAR(80) NOT NULL DEFAULT '', bio VARCHAR(300) NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS repositories (
 id BIGSERIAL PRIMARY KEY, owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name VARCHAR(100) NOT NULL, description VARCHAR(350) NOT NULL DEFAULT '',
 visibility VARCHAR(10) NOT NULL DEFAULT 'public' CHECK(visibility IN ('public','private')),
 default_branch VARCHAR(100) NOT NULL DEFAULT 'main', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(owner_id,name)
);
CREATE TABLE IF NOT EXISTS files (
 id BIGSERIAL PRIMARY KEY, repo_id BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
 path TEXT NOT NULL, kind VARCHAR(8) NOT NULL CHECK(kind IN ('file','dir')),
 content TEXT NOT NULL DEFAULT '', updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(repo_id,path)
);
CREATE TABLE IF NOT EXISTS commits (
 id BIGSERIAL PRIMARY KEY, repo_id BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
 author_id BIGINT REFERENCES users(id) ON DELETE SET NULL, message VARCHAR(200) NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS file_versions (
 id BIGSERIAL PRIMARY KEY, file_id BIGINT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
 commit_id BIGINT REFERENCES commits(id) ON DELETE SET NULL, content TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS stars (
 user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 repo_id BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(user_id,repo_id)
);
CREATE TABLE IF NOT EXISTS issues (
 id BIGSERIAL PRIMARY KEY, repo_id BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
 author_id BIGINT REFERENCES users(id) ON DELETE SET NULL, title VARCHAR(200) NOT NULL,
 body TEXT NOT NULL DEFAULT '', state VARCHAR(10) NOT NULL DEFAULT 'open' CHECK(state IN ('open','closed')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_repos_owner ON repositories(owner_id);
CREATE INDEX IF NOT EXISTS idx_files_repo ON files(repo_id);
CREATE INDEX IF NOT EXISTS idx_commits_repo ON commits(repo_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_issues_repo ON issues(repo_id,created_at DESC);
`;
const userOk=s=>/^[a-zA-Z0-9-]{3,39}$/.test(s||'');
const repoOk=s=>/^[a-zA-Z0-9._-]{1,100}$/.test(s||'') && s!=='.' && s!=='..';
const pathOk=s=>typeof s==='string'&&s.length>0&&s.length<=500&&!s.startsWith('/')&&s.split('/').every(x=>x&&x!=='.'&&x!=='..'&&!x.includes('\\'));
const tokenOf=req=>(req.headers.authorization||'').replace(/^Bearer\s+/i,'');
function optionalUser(req){try{return jwt.verify(tokenOf(req),process.env.JWT_SECRET,{issuer:'xsquad-github'})}catch{return null}}
function requireUser(req,res,next){const u=optionalUser(req);if(!u)return res.status(401).json({error:'Authentication required'});req.user=u;next()}
function ownerOnly(req,res,next){if(String(req.repo.owner_id)!==String(req.user.sub))return res.status(403).json({error:'Repository owner permission required'});next()}
async function findRepo(owner,name){const q=await pool.query(`SELECT r.*,u.username AS owner FROM repositories r JOIN users u ON u.id=r.owner_id WHERE lower(u.username)=lower($1) AND lower(r.name)=lower($2)`,[owner,name]);return q.rows[0]||null}
async function repoAccess(req,res,next){try{const repo=await findRepo(req.params.owner,req.params.repo);const user=optionalUser(req);if(!repo||!(repo.visibility==='public'||(user&&String(repo.owner_id)===String(user.sub))))return res.status(404).json({error:'Repository not found'});req.repo=repo;req.user=user;next()}catch(e){next(e)}}
const api=(fn)=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next);

app.get('/api/health',api(async(_req,res)=>{await pool.query('SELECT 1');res.json({ok:true,service:'xsquad-github-v2',database:'connected',aiConfigured:Boolean(process.env.GOOGLE_API_KEY)})}));
app.post('/api/auth/register',api(async(req,res)=>{
 const {username,email,password}=req.body||{};
 if(!userOk(username)||typeof email!=='string'||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||typeof password!=='string'||password.length<10||password.length>128)return res.status(400).json({error:'Invalid username, email, or password (10–128 characters required)'});
 const hash=await bcrypt.hash(password,12);
 try{const q=await pool.query('INSERT INTO users(username,email,password_hash,display_name) VALUES($1,lower($2),$3,$1) RETURNING id,username,email,display_name,bio,created_at',[username,email,hash]);const user=q.rows[0];const token=jwt.sign({sub:String(user.id),username:user.username},process.env.JWT_SECRET,{expiresIn:'7d',issuer:'xsquad-github'});res.status(201).json({user,token})}catch(e){if(e.code==='23505')return res.status(409).json({error:'Username or email already exists'});throw e}
}));
app.post('/api/auth/login',api(async(req,res)=>{
 const {login,password}=req.body||{};if(typeof login!=='string'||typeof password!=='string')return res.status(400).json({error:'Login and password required'});
 const q=await pool.query('SELECT * FROM users WHERE lower(username)=lower($1) OR lower(email)=lower($1)',[login]);const u=q.rows[0];
 if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:'Incorrect login or password'});
 const user={id:u.id,username:u.username,email:u.email,display_name:u.display_name,bio:u.bio};const token=jwt.sign({sub:String(u.id),username:u.username},process.env.JWT_SECRET,{expiresIn:'7d',issuer:'xsquad-github'});res.json({user,token})
}));
app.get('/api/me',requireUser,api(async(req,res)=>{const q=await pool.query('SELECT id,username,email,display_name,bio,created_at FROM users WHERE id=$1',[req.user.sub]);res.json({user:q.rows[0]||null})}));
app.patch('/api/me',requireUser,api(async(req,res)=>{const {display_name='',bio=''}=req.body||{};if(typeof display_name!=='string'||display_name.length>80||typeof bio!=='string'||bio.length>300)return res.status(400).json({error:'Invalid profile fields'});const q=await pool.query('UPDATE users SET display_name=$1,bio=$2 WHERE id=$3 RETURNING id,username,email,display_name,bio',[display_name,bio,req.user.sub]);res.json({user:q.rows[0]})}));
app.get('/api/users/:username/repos',api(async(req,res)=>{const user=optionalUser(req);const q=await pool.query(`SELECT r.name,r.description,r.visibility,r.default_branch,r.created_at,r.updated_at,(SELECT count(*)::int FROM stars s WHERE s.repo_id=r.id) AS stars FROM repositories r JOIN users u ON u.id=r.owner_id WHERE lower(u.username)=lower($1) AND (r.visibility='public' OR r.owner_id=$2) ORDER BY r.updated_at DESC`,[req.params.username,user?.sub||null]);res.json({items:q.rows})}));
app.post('/api/repos',requireUser,api(async(req,res)=>{const {name,description='',visibility='public'}=req.body||{};if(!repoOk(name)||typeof description!=='string'||description.length>350||!['public','private'].includes(visibility))return res.status(400).json({error:'Invalid repository details'});try{const q=await pool.query('INSERT INTO repositories(owner_id,name,description,visibility) VALUES($1,$2,$3,$4) RETURNING *',[req.user.sub,name,description,visibility]);await pool.query('INSERT INTO commits(repo_id,author_id,message) VALUES($1,$2,$3)',[q.rows[0].id,req.user.sub,'Initial commit']);res.status(201).json({repository:q.rows[0]})}catch(e){if(e.code==='23505')return res.status(409).json({error:'Repository already exists'});throw e}}));
app.get('/api/repos/:owner/:repo',repoAccess,api(async(req,res)=>{const [files,stars,issues]=await Promise.all([pool.query('SELECT path,kind,updated_at FROM files WHERE repo_id=$1 ORDER BY path',[req.repo.id]),pool.query('SELECT count(*)::int AS count FROM stars WHERE repo_id=$1',[req.repo.id]),pool.query("SELECT count(*)::int AS count FROM issues WHERE repo_id=$1 AND state='open'",[req.repo.id])]);res.json({repository:{name:req.repo.name,owner:req.repo.owner,description:req.repo.description,visibility:req.repo.visibility,default_branch:req.repo.default_branch,stars:stars.rows[0].count,open_issues:issues.rows[0].count},items:files.rows})}));
app.get('/api/repos/:owner/:repo/contents',repoAccess,api(async(req,res)=>{const q=await pool.query('SELECT path,kind,updated_at FROM files WHERE repo_id=$1 ORDER BY kind DESC,path',[req.repo.id]);res.json({items:q.rows.map(f=>({...f,name:f.path.split('/').pop(),type:f.kind==='dir'?'dir':'file'}))})}));
app.post('/api/repos/:owner/:repo/contents',requireUser,repoAccess,ownerOnly,api(async(req,res)=>{
 const {name,path:filePath,type,content='',message='Update file'}=req.body||{};const target=filePath||name;
 if(!pathOk(target)||!['file','dir'].includes(type)||typeof content!=='string'||Buffer.byteLength(content)>MAX_FILE_BYTES)return res.status(400).json({error:'Invalid path, type, or file too large'});
 const client=await pool.connect();try{await client.query('BEGIN');const q=await client.query(`INSERT INTO files(repo_id,path,kind,content) VALUES($1,$2,$3,$4) ON CONFLICT(repo_id,path) DO UPDATE SET kind=EXCLUDED.kind,content=EXCLUDED.content,updated_at=NOW() RETURNING *`,[req.repo.id,target,type,type==='file'?content:'']);if(type==='file'){const c=await client.query('INSERT INTO commits(repo_id,author_id,message) VALUES($1,$2,$3) RETURNING id',[req.repo.id,req.user.sub,String(message).slice(0,200)]);await client.query('INSERT INTO file_versions(file_id,commit_id,content) VALUES($1,$2,$3)',[q.rows[0].id,c.rows[0].id,content])}await client.query('UPDATE repositories SET updated_at=NOW() WHERE id=$1',[req.repo.id]);await client.query('COMMIT');res.status(201).json({ok:true,item:q.rows[0]})}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}));
app.get('/api/repos/:owner/:repo/file',repoAccess,api(async(req,res)=>{const target=req.query.path;if(!pathOk(target))return res.status(400).json({error:'Invalid file path'});const q=await pool.query("SELECT path,content,updated_at FROM files WHERE repo_id=$1 AND path=$2 AND kind='file'",[req.repo.id,target]);if(!q.rowCount)return res.status(404).json({error:'File not found'});res.json(q.rows[0])}));
app.delete('/api/repos/:owner/:repo/contents',requireUser,repoAccess,ownerOnly,api(async(req,res)=>{const target=req.query.path;if(!pathOk(target))return res.status(400).json({error:'Invalid file path'});const q=await pool.query('DELETE FROM files WHERE repo_id=$1 AND path=$2 RETURNING id',[req.repo.id,target]);if(!q.rowCount)return res.status(404).json({error:'File not found'});res.json({ok:true})}));
app.get('/api/repos/:owner/:repo/commits',repoAccess,api(async(req,res)=>{const q=await pool.query('SELECT c.id,c.message,c.created_at,u.username AS author FROM commits c LEFT JOIN users u ON u.id=c.author_id WHERE c.repo_id=$1 ORDER BY c.created_at DESC LIMIT 100',[req.repo.id]);res.json({items:q.rows})}));
app.get('/api/repos/:owner/:repo/issues',repoAccess,api(async(req,res)=>{const q=await pool.query('SELECT i.id,i.title,i.body,i.state,i.created_at,u.username AS author FROM issues i LEFT JOIN users u ON u.id=i.author_id WHERE i.repo_id=$1 ORDER BY i.created_at DESC LIMIT 100',[req.repo.id]);res.json({items:q.rows})}));
app.post('/api/repos/:owner/:repo/issues',requireUser,repoAccess,api(async(req,res)=>{const {title,body=''}=req.body||{};if(typeof title!=='string'||!title.trim()||title.length>200||typeof body!=='string'||body.length>10000)return res.status(400).json({error:'Invalid issue'});const q=await pool.query('INSERT INTO issues(repo_id,author_id,title,body) VALUES($1,$2,$3,$4) RETURNING *',[req.repo.id,req.user.sub,title.trim(),body]);res.status(201).json({issue:q.rows[0]})}));
app.patch('/api/repos/:owner/:repo/issues/:id',requireUser,repoAccess,api(async(req,res)=>{if(String(req.repo.owner_id)!==String(req.user.sub))return res.status(403).json({error:'Repository owner permission required'});const state=req.body?.state;if(!['open','closed'].includes(state))return res.status(400).json({error:'State must be open or closed'});const q=await pool.query('UPDATE issues SET state=$1 WHERE id=$2 AND repo_id=$3 RETURNING *',[state,req.params.id,req.repo.id]);if(!q.rowCount)return res.status(404).json({error:'Issue not found'});res.json({issue:q.rows[0]})}));
app.post('/api/repos/:owner/:repo/star',requireUser,repoAccess,api(async(req,res)=>{const exists=await pool.query('SELECT 1 FROM stars WHERE user_id=$1 AND repo_id=$2',[req.user.sub,req.repo.id]);if(exists.rowCount)await pool.query('DELETE FROM stars WHERE user_id=$1 AND repo_id=$2',[req.user.sub,req.repo.id]);else await pool.query('INSERT INTO stars(user_id,repo_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[req.user.sub,req.repo.id]);const count=await pool.query('SELECT count(*)::int AS count FROM stars WHERE repo_id=$1',[req.repo.id]);res.json({starred:!exists.rowCount,stars:count.rows[0].count})}));
app.get('/raw/:owner/:repo/:branch/*',api(async(req,res)=>{const repo=await findRepo(req.params.owner,req.params.repo);const user=optionalUser(req);if(!repo||!(repo.visibility==='public'||(user&&String(repo.owner_id)===String(user.sub))))return res.status(404).send('Not Found');const target=req.params[0];if(!pathOk(target))return res.status(400).send('Bad Request');const q=await pool.query("SELECT content FROM files WHERE repo_id=$1 AND path=$2 AND kind='file'",[repo.id,target]);if(!q.rowCount)return res.status(404).send('Not Found');res.type('text/plain').set('X-Content-Type-Options','nosniff').send(q.rows[0].content)}));
app.post('/api/ai/chat',requireUser,api(async(req,res)=>{if(!process.env.GOOGLE_API_KEY)return res.status(503).json({error:'Google AI is not configured. Set GOOGLE_API_KEY on Render.'});const prompt=req.body?.message;if(typeof prompt!=='string'||!prompt.trim()||prompt.length>12000)return res.status(400).json({error:'Message must be 1–12000 characters'});const ai=new GoogleGenAI({apiKey:process.env.GOOGLE_API_KEY});const result=await ai.models.generateContent({model:process.env.GEMINI_MODEL||'gemini-2.5-flash',contents:[{role:'user',parts:[{text:`You are Xsquad GitHub AI, a coding assistant. Give accurate, safe, concise coding help. Do not claim to have changed files or run code unless tools actually did so. User request:\n${prompt}`}]}]});res.json({reply:result.text||'No response returned.'})}));
app.use(express.static(path.resolve(__dirname,'../../client'),{extensions:['html']}));
app.get('*',(req,res)=>res.sendFile(path.resolve(__dirname,'../../client/index.html')));
app.use((err,req,res,next)=>{console.error(err);if(res.headersSent)return next(err);res.status(500).json({error:process.env.NODE_ENV==='production'?'Internal server error':err.message})});

async function start(){if(!process.env.DATABASE_URL)console.warn('DATABASE_URL missing: API database routes will not work until configured.');else await pool.query(schema);app.listen(PORT,'0.0.0.0',()=>console.log(`Xsquad GitHub listening on ${PORT}`))}
start().catch(err=>{console.error('Startup failed:',err);process.exit(1)});
                      
