/* eslint-disable class-methods-use-this */
/* eslint-disable lines-between-class-members */
import { JWT_KEY } from '@config';
import { UserInterface } from '@interfaces/User.interface';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

class UserService {
  protected model = new PrismaClient();
  find() {
    return this.model.user.findMany();
  }

  findOne(data: string | Partial<UserInterface>) {
    if (typeof data === 'object') return this.model.user.findFirst({ where: <any>data });
    return this.model.user.findFirst({
      where: {
        id: <number>(<unknown>data),
      },
    });
  }

  update(query: string | Partial<UserInterface>, data: Partial<UserInterface>) {
    if (typeof query === 'object') return this.model.user.update({ where: <any>query, data });
    return this.model.user.update({
      where: {
        id: <number>(<unknown>query),
      },
      data,
    });
  }

  // updateMany(query: Partial<UserInterface>, data: Partial<UserInterface>) {
  //   return this.model.updateMany(query, data);
  // }
  create(data: UserInterface) {
    return this.model.user.create({ data });
  }

  delete(data: string | Partial<UserInterface>) {
    if (typeof data === 'object') return this.model.user.delete({ where: <any>data });
    return this.model.user.delete({
      where: {
        id: <number>(<unknown>data),
      },
    });
  }

  // load(id: string, data: Partial<UserInterface> | Partial<UserInterface>[]) {
  //   if (Array.isArray(data)) {
  //     return this.model.findByIdAndUpdate(id, { $push: { $each: data } }, { new: true });
  //   }
  //   return this.model.findByIdAndUpdate(id, { $push: data }, { new: true });
  // }

  async genHash(password: string) {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(password, salt);
  }

  comparePasswords(password: string, user: UserInterface) {
    return bcrypt.compare(password, user.password);
  }

  getSignedToken(user: UserInterface & { id: string }) {
    // eslint-disable-next-line no-underscore-dangle
    return jwt.sign({ id: user.id }, <string>JWT_KEY, {});
  }
}

export default new UserService();
