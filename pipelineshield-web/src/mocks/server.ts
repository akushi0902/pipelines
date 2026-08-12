import { setupServer } from 'msw/node';
import { catalogueHandlers } from './handlers/catalogue';
import { adminHandlers } from './handlers/admin';
import { uploadHandlers } from './handlers/upload';

export const server = setupServer(...catalogueHandlers, ...adminHandlers, ...uploadHandlers);
