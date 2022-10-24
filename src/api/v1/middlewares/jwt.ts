/* eslint-disable no-underscore-dangle */
/* eslint-disable consistent-return */
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import HttpError from '@helpers/HttpError';
import { MESSAGES, JWT_KEY } from '@config';
import UserService from '@services/User.service';
import { UserInterface } from '@interfaces/User.interface';

declare module 'express' {
  // eslint-disable-next-line no-shadow
  export interface Request {
    user?: UserInterface;
  }
}
// eslint-disable-next-line consistent-return
export const verify = (roles: number[]) => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const token =
      req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer'
        ? req.headers.authorization.split(' ')[1]
        : null;

    if (!token) {
      throw new HttpError(MESSAGES.UNAUTHORIZED, 401);
    }
    const decoded = <UserInterface & { id: string }>jwt.verify(token, <string>JWT_KEY);

    const user = await UserService.findOne(decoded.id);

    if (!user) {
      throw new HttpError(MESSAGES.UNAUTHORIZED, 401);
    }

    const hasPermission = user.roles.some((val) => roles.includes(val));

    if (!hasPermission) {
      throw new HttpError(MESSAGES.INVALID_PERMISSION, 403);
    }

    req.user = user;

    return next();
  } catch (error) {
    next(error);
  }
};
