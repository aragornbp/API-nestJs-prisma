/* eslint-disable @typescript-eslint/no-empty-function */
/* eslint-disable prettier/prettier */
import { Controller, Get, UseGuards, Req, Patch } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';

@Controller('users')
export class UserController {

  @UseGuards(AuthGuard('jwt'))
  @Get('me')
  getMe(@Req() req: Request){
    console.log({user: req.user})
    return req.user
  }

  @UseGuards(AuthGuard('jwt'))
  @Patch()
  editUser(){}

}
