import { MESSAGES } from '@config';
import mongoose from 'mongoose';

export default async (url: string) => {
  try {
    await mongoose.connect(url);
    console.info(MESSAGES.DB_CONNECTED);
  } catch (error) {
    console.error(error);
  }
};
