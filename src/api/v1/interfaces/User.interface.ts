/* eslint-disable no-unused-vars */
/* eslint-disable no-shadow */
export interface UserInterface {
  fullname: string;
  username: string;
  password: string;
  roles: Array<number>;
}

export enum Roles {
  superAdmin,
  admin,
  student,
  lecturer,
  examOfficer,
  HOD,
  dean,
}
