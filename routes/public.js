import express from 'express'
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'



const prisma = new PrismaClient()
const router = express.Router()

const JWT_SECRET = process.env.JWT_SECRET

//Cadastro
router.post('/cadastro', async (req, res) => {

    try{
        const user = req.body

        const salt = await bcrypt.genSalt(10) // Me diz qual a força da criptografia
        const hashPassword = await bcrypt.hash(user.password, salt) // criptografa a senha

        const userDB = await prisma.user.create({
            data: {
                email: user.email,
                name: user.name,
                password: hashPassword,
            },
        })
    
        res.status(201).json(userDB)
    }
    catch(error){
        res.status(500).json({ message: 'Erro no Servidor, tente novamente.'})
    }
})


//login
router.post('/login', async (req,res) => {

    try{

        const userInfo = req.body


        //Busca o usuário no banco de dados
        const user = await prisma.user.findUnique({ 
            where: { email: userInfo.email },
        })

        //Verifica se o usuário existe
        if(!user){
           return res.status(404).json({ message: 'Usuário não encontrado'})
        }
        
        //Compara a senha do banco com a que o usuário digitou
        const isMatch = await bcrypt.compare(userInfo.password, user.password)


        //Verifica se a senha digitada e a senha do banco são iguais, caso não seja, retorna 'Senha inválida'
        if(!isMatch){
            return res.status(400).json({ message: 'Senha inválida'})
        }

        //Gerar o Token JWT
        const token = jwt.sign({id: user.id}, JWT_SECRET, {expiresIn: '1d'})

        res.status(200).json(token)

    } catch(error){
        res.status(500).json({ message: 'Algo deu errado, por favor, tente novamente!'})
    }
})

export default router