/* eslint-disable import/prefer-default-export */
import { Request, Response, NextFunction } from 'express';
import HttpError from '@helpers/HttpError';

export const httpErrorHandler = (
  err: HttpError | Error,
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const error = { ...err };
  error.message = err.message;

  let statusCode: number;
  if ('statusCode' in error) {
    statusCode = error.statusCode;
  } else {
    statusCode = 500;
  }

  res.status(statusCode).json({
    success: false,
    msg: error.message || 'Server Error',
    error,
    errors: [{ message: error.message || 'Server Error' }],
  });
};
