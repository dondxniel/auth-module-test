/* eslint-disable lines-between-class-members */
import { Roles } from '@interfaces/User.interface';
import { httpErrorHandler } from '@middlewares/errorHandler';
import { verify } from '@middlewares/jwt';
import { error404 } from '@middlewares/notFoundHandler';
import authRoute from '@routes/auth.route';
import userRoute from '@routes/user.route';
import cors from 'cors';
import express, { Application } from 'express';
import morgan from 'morgan';

class App {
  private app: Application;
  constructor() {
    this.app = express();
    this.initMiddlewares();
    this.initRoutes();
    this.initErrorHandlers();
  }

  private initMiddlewares() {
    this.app.use(express.json());
    this.app.use(cors());
    this.app.use(morgan('dev'));
    this.app.use(express.urlencoded({ extended: true }));
  }

  private initRoutes() {
    this.app.use('/api/v1/', authRoute.initRoutes());
    this.app.use('/api/v1/users', verify([Roles.admin, Roles.superAdmin, Roles.student]), userRoute.initRoutes());
  }

  private initErrorHandlers() {
    this.app.use('*', error404);
    this.app.use(httpErrorHandler);
  }

  public instance() {
    return this.app;
  }
}

export default App;
