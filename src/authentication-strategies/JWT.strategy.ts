const jwt = require('jsonwebtoken');
import {promisify} from 'util';
const verifyAsync = promisify(jwt.verify);
// Consider turn it to a binding
const SECRET = 'secretforjwt';
import {Request, HttpErrors} from '@loopback/rest';
import {UserProfile} from '@loopback/authentication';
import * as _ from 'lodash';

export class JWTStrategy {
  // tslint:disable-next-line:no-any
  async authenticate(request: Request): Promise<UserProfile | undefined> {
    // there is a discussion regarding how to retrieve the token,
    // see comment https://github.com/strongloop/loopback-next/issues/1997#issuecomment-451054806
    const token = request.query.token || request.headers['authorization'];
    if (token) {
      try {
        const decoded = await verifyAsync(token, SECRET);
        return Promise.resolve(_.pick(decoded, ['id', 'email']));
      } catch (err) {
        if (err)
          return Promise.reject(
            new HttpErrors.Unauthorized('Could not decode the JWT token!'),
          );
      }
    } else {
      return Promise.reject(new HttpErrors.Unauthorized('Token not found!'));
    }
  }
}
