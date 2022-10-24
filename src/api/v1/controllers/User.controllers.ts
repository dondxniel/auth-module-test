/* eslint-disable lines-between-class-members */
import HttpError from '@helpers/HttpError';
import HttpResponse from '@helpers/HttpResponse';
import { UserInterface } from '@interfaces/User.interface';
import UserService from '@services/User.service';
import { NextFunction, Request, Response } from 'express';

class UserController {
  protected service = UserService;
  protected resourceId = 'userId';
  protected resource = 'user';
  create = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const data = <UserInterface>req.body;
      const result = await this.service.create(data);
      HttpResponse.send(res, result);
    } catch (error) {
      next(error);
    }
  };
  get = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await this.service.find();
      HttpResponse.send(res, result);
    } catch (error) {
      next(error);
    }
  };
  getOne = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await this.service.findOne(req.params[this.resourceId]);
      if (!result) throw new HttpError(`${this.resource} not found`, 404);
      HttpResponse.send(res, result);
    } catch (error) {
      next(error);
    }
  };

  update = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await this.service.update(req.params[this.resourceId], req.body);
      if (!result) throw new HttpError(`${this.resource} not found`, 404);
      HttpResponse.send(res, result);
    } catch (error) {
      next(error);
    }
  };

  delete = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await this.service.delete(req.params[this.resourceId]);
      if (!result) throw new HttpError(`${this.resource} not found`, 404);
      HttpResponse.send(res, result);
    } catch (error) {
      next(error);
    }
  };
}

export default UserController;
