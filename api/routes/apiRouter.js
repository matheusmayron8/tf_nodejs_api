require('dotenv').config()
const express = require('express')
const bcrypt = require('bcryptjs') 
const jwt = require('jsonwebtoken') 

let apiRouter = express.Router()
const knex = require('knex')({
    client: 'pg',
    debug: true,
    connection: {
        connectionString: process.env.DATABASE_URL,
        ssl: {rejectUnauthorized: false}
    }
})

let checkToken = (req, res, next) => {
    let authToken = req.headers["authorization"]
    if(!authToken) {
        res.status(401).json({message: 'Token de acesso requerida'})
        return
    }
    else {
        let token = authToken.split(' ')[1]
        req.token = token
    }

    jwt.verify(req.token, process.env.SECRET_KEY, (err, decodeToken) => {
        if(err) {
            res.status(401).json({message: 'Acesso negado'})
            return 
        }

        req.userId = decodeToken.id
        next()
    })
}


const endpoint = '/'

apiRouter.get(endpoint + 'notes', checkToken, (req, res) => {
    knex.select('*').from('notes').where({userid: req.userId})
    .then( notes => res.status(200).json(notes))
    .catch(err => {
        res.status(500).json({
            message: 'Erro ao recuperar notas - ' + err.message
        })
    })
})

apiRouter.get(endpoint + 'notes/:id', checkToken, (req, res) => {
    let id = req.params.id
    knex.select('*').from('notes').where({
        id: id,
        userid: req.userId
    }).first()
    .then(note => {
        if (note) res.status(200).json(note)
        else res.status(404).send()
    })
    .catch(err => {
        res.status(500).json({
            message: 'Erro ao recuperar notas - ' + err.message
        })
    })
})

//Create new client
apiRouter.post(endpoint + 'notes', checkToken, (req, res) => {
    let body = req.body
    if(body.note && req.userId){
        knex('notes').insert({note: body.note, userid: req.userId})
        .then( result => {
            if(result) {
                res.status(201).json({message: 'Nota adicionada com sucesso.'})
            } else {
                res.status(500).json({message: 'Erro ao cadastrar nota'})
            }
        })
        .catch(err => res.status(500).json({message: `Erro ao cadastrar nota - ${err.message}`}))
    } else {
        res.status(400).json({message: 'Campo [note] é obrigatório.'})
    }
})

apiRouter.put(endpoint + 'notes/:id', checkToken, (req, res) => {
    let id = req.params.id
    console.log(req.body)
    if (!req.body.completed) {
        res.status(400).json({message: 'Campo [completed] é obrigatório.'})
        return
    }

    knex('notes')
        .update({completed: req.body.completed})
        .where({id: id, userid: req.userId})
        .then( result => {
            if (result) res.status(200).json({message: 'Atualizado com sucesso.'})
            else res.status(500).json({message: 'Não foi possível atualizar a nota.'})
        })
        .catch(err => res.status(500).json({message: `Não foi possível atualizar a nota - ${err.message}`}))
})

apiRouter.delete(endpoint + 'notes/:id', checkToken, (req, res) => {
    let id = req.params.id
    knex('notes')
        .del()
        .where({id: id, userid: req.userId})
        .then( result => {
            if(result) res.status(204).send()
            else res.status(500).json({message: 'Não foi possível excluir a nota'})
        })
        .catch(err => res.status(500).json({message: `Não foi possível excluir a nota - ${err.message}`}))
})

//Security routes
apiRouter.post(endpoint + 'user/register', (req, res) => {
    knex('usuario')
        .insert({
            name: req.body.name,
            login: req.body.login,
            password: bcrypt.hashSync(req.body.password, 8),
            email: req.body.email
        }, ['id'])
        .then((result) => {
            let user = result[0]
            res.status(201).json({id: user.id})
            return
        })
        .catch(err => {
            res.status(500).json({
                message: 'Erro ao registrar usuário - ' + err.message
            })
        })
})

apiRouter.post(endpoint + 'user/login', (req, res) => {
    knex
    .select('*')
    .from('usuario')
    .where({login: req.body.login})
    .then( users => {
        if(users.length) {
            let user = users[0]
            let checkPassword = bcrypt.compareSync(req.body.password, user.password)
            if(checkPassword) {
                var jwtToken = jwt.sign(
                    {id: user.id},
                    process.env.SECRET_KEY,
                    {expiresIn: 3600}
                )

                res.status(200).json({
                    id: user.id,
                    login: user.login,
                    roles: user.roles,
                    token: jwtToken
                })
                return
            } else {
                res.status(401).json({message: 'Login ou senha incorretos'})
            }
        }
    })
    .catch(err => {
        res.status(500).json({
            message: 'Erro ao verificar login - ' + err.message
        })
    })
})

apiRouter.use((req, res) => {
    res.status(404).send("404 - Recurso não encontrado")
})


module.exports = apiRouter