/* eslint-disable import/prefer-default-export */
import { MESSAGES } from '@config';
import { Request, Response } from 'express';

export const error404 = (req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    message: MESSAGES.ROUTE_DOES_NOT_EXIST,
  });
};
