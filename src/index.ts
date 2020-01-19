import { open } from 'sqlite';
import { UserAuthenticator } from 'thomasio-auth-js-common/lib/server';

export function getUserAuthenticator<T>(dbFileName: string): UserAuthenticator<T> {
	const dbPromise = open(dbFileName);
}
