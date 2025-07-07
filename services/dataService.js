const { getDatabase } = require('../config/database');

/**
 * Data service to abstract database operations
 * This allows us to switch between SQLite and PostgreSQL without changing the application logic
 */
class DataService {
  constructor() {
    this.db = getDatabase();
  }

  /**
   * Execute a query against the database
   * @param {string} query - SQL query
   * @param {Array} params - Query parameters
   */
  async query(query, params = []) {
    if (this.db.type === 'postgres') {
      const { rows } = await this.db.pg.query(query, params);
      return rows;
    } else {
      // Convert the SQLite query to use named parameters
      let sqliteQuery = query;
      
      // Replace PostgreSQL style $1, $2 with SQLite's ?
      if (params.length > 0) {
        for (let i = 1; i <= params.length; i++) {
          const regex = new RegExp('\\$' + i, 'g');
          sqliteQuery = sqliteQuery.replace(regex, '?');
        }
      }
      
      // Execute the SQLite query
      if (sqliteQuery.trim().toLowerCase().startsWith('select')) {
        return this.db.sqlite.prepare(sqliteQuery).all(...params);
      } else {
        const stmt = this.db.sqlite.prepare(sqliteQuery);
        const result = stmt.run(...params);
        return [{ changes: result.changes, lastInsertRowid: result.lastInsertRowid }];
      }
    }
  }

  /**
   * Insert data into a table
   * @param {string} table - Table name
   * @param {Object} data - Data to insert
   */
  async insert(table, data) {
    const keys = Object.keys(data);
    const values = Object.values(data);
    
    if (this.db.type === 'postgres') {
      const placeholders = keys.map((_, i) => `$${i + 1}`).join(', ');
      const query = `INSERT INTO ${table} (${keys.join(', ')}) VALUES (${placeholders}) RETURNING *`;
      const { rows } = await this.db.pg.query(query, values);
      return rows[0];
    } else {
      const placeholders = keys.map(() => '?').join(', ');
      const query = `INSERT INTO ${table} (${keys.join(', ')}) VALUES (${placeholders})`;
      const stmt = this.db.sqlite.prepare(query);
      const result = stmt.run(...values);
      return { id: result.lastInsertRowid };
    }
  }

  /**
   * Update data in a table
   * @param {string} table - Table name
   * @param {Object} data - Data to update
   * @param {Object} where - Condition for update
   */
  async update(table, data, where) {
    const updateKeys = Object.keys(data);
    const updateValues = Object.values(data);
    const whereKeys = Object.keys(where);
    const whereValues = Object.values(where);
    
    const allValues = [...updateValues, ...whereValues];
    
    if (this.db.type === 'postgres') {
      const setClause = updateKeys.map((key, i) => `${key} = $${i + 1}`).join(', ');
      const whereClause = whereKeys.map((key, i) => `${key} = $${updateKeys.length + i + 1}`).join(' AND ');
      const query = `UPDATE ${table} SET ${setClause} WHERE ${whereClause} RETURNING *`;
      const { rows } = await this.db.pg.query(query, allValues);
      return rows;
    } else {
      const setClause = updateKeys.map(key => `${key} = ?`).join(', ');
      const whereClause = whereKeys.map(key => `${key} = ?`).join(' AND ');
      const query = `UPDATE ${table} SET ${setClause} WHERE ${whereClause}`;
      const stmt = this.db.sqlite.prepare(query);
      const result = stmt.run(...allValues);
      return { changes: result.changes };
    }
  }

  /**
   * Delete data from a table
   * @param {string} table - Table name
   * @param {Object} where - Condition for deletion
   */
  async delete(table, where) {
    const whereKeys = Object.keys(where);
    const whereValues = Object.values(where);
    
    if (this.db.type === 'postgres') {
      const whereClause = whereKeys.map((key, i) => `${key} = $${i + 1}`).join(' AND ');
      const query = `DELETE FROM ${table} WHERE ${whereClause} RETURNING *`;
      const { rows } = await this.db.pg.query(query, whereValues);
      return rows;
    } else {
      const whereClause = whereKeys.map(key => `${key} = ?`).join(' AND ');
      const query = `DELETE FROM ${table} WHERE ${whereClause}`;
      const stmt = this.db.sqlite.prepare(query);
      const result = stmt.run(...whereValues);
      return { changes: result.changes };
    }
  }

  /**
   * Find data in a table
   * @param {string} table - Table name
   * @param {Object} where - Condition for finding
   */
  async find(table, where = {}) {
    const whereKeys = Object.keys(where);
    const whereValues = Object.values(where);
    
    if (whereKeys.length === 0) {
      return this.query(`SELECT * FROM ${table}`);
    }
    
    if (this.db.type === 'postgres') {
      const whereClause = whereKeys.map((key, i) => `${key} = $${i + 1}`).join(' AND ');
      return this.query(`SELECT * FROM ${table} WHERE ${whereClause}`, whereValues);
    } else {
      const whereClause = whereKeys.map(key => `${key} = ?`).join(' AND ');
      return this.query(`SELECT * FROM ${table} WHERE ${whereClause}`, whereValues);
    }
  }

  /**
   * Find a single record in a table
   * @param {string} table - Table name
   * @param {Object} where - Condition for finding
   */
  async findOne(table, where) {
    const result = await this.find(table, where);
    return result.length > 0 ? result[0] : null;
  }
}

module.exports = new DataService();
