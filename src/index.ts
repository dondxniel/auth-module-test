import App from '@app';
import { PORT, DB_URI, MESSAGES } from '@config';
import db from '@db';

const app = new App().instance();

app.listen(<number>(<unknown>PORT), async () => {
  await db(<string>DB_URI);
  console.log(MESSAGES.SERVER_STARTED);
});
