import { Schema, model } from 'mongoose';
import { UserInterface } from '@interfaces/User.interface';

const userSchema = new Schema<UserInterface>({
  fullname: { type: String },
  username: { type: String, unique: true },
  password: { type: String },
  roles: [{ type: Number }],
});

export default model('users', userSchema);
